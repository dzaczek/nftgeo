// nftgeo-ui - a small, read-only local dashboard for the nftgeo firewall.
// Phase A of the P6 roadmap: it shells out to nft / journalctl / nftgeo-update
// and geolocates dropped IPs from the local ipdeny zones. It never writes; the
// firewall's source of truth stays in /etc/nftgeo and the CLI.
package main

import (
	"embed"
	"encoding/json"
	"flag"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed assets
var assetsFS embed.FS

var (
	fam      = env("TABLE_FAMILY", "inet")
	table    = env("TABLE_NAME", "nftgeo")
	zoneDir  = env("ZONE_DIR", "/var/lib/nftgeo/zones")
	engine   = env("NFTGEO_UPDATE", "/usr/local/sbin/nftgeo-update")
)

func env(k, def string) string {
	if v, ok := os.LookupEnv(k); ok && v != "" {
		return v
	}
	return def
}

// ---- shelling out -----------------------------------------------------------

func run(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	return string(out), err
}

func version() string {
	out, err := run(engine, "--version")
	if err != nil {
		return "unknown"
	}
	f := strings.Fields(strings.TrimSpace(out))
	if len(f) > 0 {
		return f[len(f)-1]
	}
	return "unknown"
}

func tableLoaded() bool {
	_, err := run("nft", "list", "table", fam, table)
	return err == nil
}

// ---- chains & counters (text parsing) --------------------------------------

type Rule struct {
	Text    string `json:"text"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
	Verdict string `json:"verdict"`
}
type Chain struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

var reCounter = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)
var reVerdict = regexp.MustCompile(`counter packets \d+ bytes \d+ (accept|drop)`)

func chains() []Chain {
	var res []Chain
	for _, hook := range []string{"input", "output", "forward"} {
		out, err := run("nft", "list", "chain", fam, table, hook)
		if err != nil {
			continue
		}
		ch := Chain{Name: hook}
		for _, line := range strings.Split(out, "\n") {
			l := strings.TrimSpace(line)
			if !strings.Contains(l, "counter packets") {
				continue
			}
			m := reCounter.FindStringSubmatch(l)
			if m == nil {
				continue
			}
			p, _ := strconv.ParseInt(m[1], 10, 64)
			b, _ := strconv.ParseInt(m[2], 10, 64)
			v := ""
			if vm := reVerdict.FindStringSubmatch(l); vm != nil {
				v = vm[1]
			}
			ch.Rules = append(ch.Rules, Rule{Text: l, Packets: p, Bytes: b, Verdict: v})
		}
		res = append(res, ch)
	}
	return res
}

// ---- sets -------------------------------------------------------------------

type Set struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Count int    `json:"count"`
}

type nftJSON struct {
	Nftables []map[string]json.RawMessage `json:"nftables"`
}

func sets() []Set {
	out, err := run("nft", "-j", "list", "table", fam, table)
	if err != nil {
		return nil
	}
	var doc nftJSON
	if json.Unmarshal([]byte(out), &doc) != nil {
		return nil
	}
	var names []struct{ Name, Type string }
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var s struct {
			Name string          `json:"name"`
			Type json.RawMessage `json:"type"`
		}
		if json.Unmarshal(raw, &s) == nil {
			t := strings.Trim(string(s.Type), `"[] `)
			names = append(names, struct{ Name, Type string }{s.Name, t})
		}
	}
	var res []Set
	for _, n := range names {
		res = append(res, Set{Name: n.Name, Type: n.Type, Count: setCount(n.Name)})
	}
	sort.Slice(res, func(i, j int) bool { return res[i].Name < res[j].Name })
	return res
}

func setCount(name string) int {
	out, err := run("nft", "-j", "list", "set", fam, table, name)
	if err != nil {
		return 0
	}
	var doc nftJSON
	if json.Unmarshal([]byte(out), &doc) != nil {
		return 0
	}
	for _, obj := range doc.Nftables {
		raw, ok := obj["set"]
		if !ok {
			continue
		}
		var s struct {
			Elem []json.RawMessage `json:"elem"`
		}
		if json.Unmarshal(raw, &s) == nil {
			return len(s.Elem)
		}
	}
	return 0
}

// ---- geolocation from the local ipdeny zones -------------------------------

type geoIndex struct {
	mu   sync.RWMutex
	v4   map[byte][]v4net // first octet -> nets
	when time.Time
}
type v4net struct {
	ip, mask uint32
	cc       string
}

var geo = &geoIndex{v4: map[byte][]v4net{}}

func (g *geoIndex) load() {
	entries, err := os.ReadDir(zoneDir)
	if err != nil {
		return
	}
	idx := map[byte][]v4net{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".v4") {
			continue
		}
		cc := strings.TrimSuffix(name, ".v4")
		data, err := os.ReadFile(zoneDir + "/" + name)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			_, n, err := net.ParseCIDR(line)
			if err != nil {
				continue
			}
			ip4 := n.IP.To4()
			if ip4 == nil {
				continue
			}
			ipu := be32(ip4)
			masku := be32(net.IP(n.Mask).To4())
			idx[ip4[0]] = append(idx[ip4[0]], v4net{ipu, masku, cc})
		}
	}
	g.mu.Lock()
	g.v4 = idx
	g.when = time.Now()
	g.mu.Unlock()
}

func (g *geoIndex) lookup(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return "" // v6 geolocation not indexed in Phase A
	}
	u := be32(ip4)
	g.mu.RLock()
	defer g.mu.RUnlock()
	best, bestMask := "", uint32(0)
	for _, n := range g.v4[ip4[0]] {
		if u&n.mask == n.ip {
			if n.mask >= bestMask { // longest prefix wins
				best, bestMask = n.cc, n.mask
			}
		}
	}
	return best
}

func be32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// ---- drops from journald ----------------------------------------------------

type Drop struct {
	Time   string `json:"time"`
	Src    string `json:"src"`
	Dst    string `json:"dst"`
	Dport  string `json:"dport"`
	Proto  string `json:"proto"`
	Dir    string `json:"dir"` // ingress|egress|forward
	CC     string `json:"cc"`
}
type DropsResp struct {
	Enabled       bool           `json:"enabled"`
	Total         int            `json:"total"`
	IngressByCC   map[string]int `json:"ingressByCC"`
	EgressByCC    map[string]int `json:"egressByCC"`
	TopPorts      map[string]int `json:"topPorts"`
	Recent        []Drop         `json:"recent"`
}

var reKV = regexp.MustCompile(`(\w+)=(\S+)`)

func drops(since string) DropsResp {
	resp := DropsResp{IngressByCC: map[string]int{}, EgressByCC: map[string]int{}, TopPorts: map[string]int{}}
	out, err := run("journalctl", "-k", "-o", "json", "--no-pager", "--since", since)
	if err != nil {
		return resp
	}
	for _, line := range strings.Split(out, "\n") {
		if !strings.Contains(line, "nftgeo-drop") {
			continue
		}
		var rec struct {
			Msg string `json:"MESSAGE"`
			TS  string `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil || !strings.Contains(rec.Msg, "nftgeo-drop") {
			continue
		}
		f := map[string]string{}
		for _, m := range reKV.FindAllStringSubmatch(rec.Msg, -1) {
			f[m[1]] = m[2]
		}
		d := Drop{Src: f["SRC"], Dst: f["DST"], Dport: f["DPT"], Proto: f["PROTO"]}
		if us, e := strconv.ParseInt(rec.TS, 10, 64); e == nil {
			d.Time = time.UnixMicro(us).UTC().Format(time.RFC3339)
		}
		in, out := f["IN"] != "", f["OUT"] != ""
		switch {
		case in && !out:
			d.Dir = "ingress"
			d.CC = geo.lookup(d.Src)
			if d.CC != "" {
				resp.IngressByCC[d.CC]++
			}
		case out && !in:
			d.Dir = "egress"
			d.CC = geo.lookup(d.Dst)
			if d.CC != "" {
				resp.EgressByCC[d.CC]++
			}
		default:
			d.Dir = "forward"
			d.CC = geo.lookup(d.Src)
		}
		if d.Dport != "" {
			resp.TopPorts[d.Dport]++
		}
		resp.Total++
		resp.Recent = append(resp.Recent, d)
	}
	// newest first, cap the recent list
	sort.Slice(resp.Recent, func(i, j int) bool { return resp.Recent[i].Time > resp.Recent[j].Time })
	if len(resp.Recent) > 200 {
		resp.Recent = resp.Recent[:200]
	}
	resp.Enabled = logDropsOn()
	return resp
}

func logDropsOn() bool {
	// A cheap heuristic: LOG_DROPS emits "log prefix" rules into the ruleset.
	out, _ := run("nft", "list", "table", fam, table)
	return strings.Contains(out, `log prefix "nftgeo-drop`)
}

// ---- http -------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func main() {
	addr := flag.String("addr", "127.0.0.1:8787", "listen address (keep it local)")
	flag.Parse()

	geo.load()
	go func() {
		for range time.Tick(6 * time.Hour) {
			geo.load()
		}
	}()

	sub, _ := fs.Sub(assetsFS, "assets")
	http.Handle("/", http.FileServer(http.FS(sub)))

	http.HandleFunc("/api/status", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{
			"version": version(),
			"loaded":  tableLoaded(),
			"chains":  chains(),
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})
	http.HandleFunc("/api/sets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, sets())
	})
	http.HandleFunc("/api/drops", func(w http.ResponseWriter, r *http.Request) {
		since := r.URL.Query().Get("since")
		if since == "" {
			since = "-24h"
		}
		writeJSON(w, drops(since))
	})

	log.Printf("nftgeo-ui: serving on http://%s (read-only)", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
