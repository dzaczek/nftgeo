// nftgeo-ui - a small local dashboard and policy editor for the nftgeo firewall.
// Phase A (read-only view) shells out to nft / journalctl / nftgeo-update and
// geolocates dropped IPs from the local ipdeny zones. Phase B adds server-side
// *drafts* that read-write sessions edit and Commit via the engine's own safe
// pipeline (validate -> plan -> apply --confirm deadman): rules.conf (M6B.1) and
// GROUP_*/REGION_* objects in a groups.d drop-in (M6B.2). No live file is touched
// until an explicit Deploy. The config files and CLI remain the single source of
// truth - the drafts are just staging copies.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

//go:embed assets
var assetsFS embed.FS

var (
	fam        = env("TABLE_FAMILY", "inet")
	table      = env("TABLE_NAME", "nftgeo")
	zoneDir    = env("ZONE_DIR", "/var/lib/nftgeo/zones")
	engine     = env("NFTGEO_UPDATE", "/usr/local/sbin/nftgeo-update")
	configFile = env("CONFIG_FILE", "/etc/nftgeo/config")
	rulesFile  = env("RULES_FILE", "/etc/nftgeo/rules.conf")
	rulesDir   = env("RULES_DIR", "/etc/nftgeo/rules.d")
	feedsDir   = env("ABUSE_FEEDS_CACHE_DIR", "/var/lib/nftgeo/feeds")
	// Optional full offline geo dataset (GEO_FULL=1): fetch every ipdeny country
	// zone into a UI-owned cache so the drop map covers all sources.
	geoFull     = env("GEO_FULL", "")
	geoCacheDir = env("GEO_CACHE_DIR", "/var/lib/nftgeo/ui-geo")
	ipdenyV4    = env("IPDENY_V4_URL", "https://www.ipdeny.com/ipblocks/data/aggregated")
)

// ISO 3166-1 alpha-2 codes (lowercase) - the ipdeny per-country zone filenames.
const isoCodes = "ad ae af ag ai al am ao ar as at au aw ax az ba bb bd be bf bg bh bi bj bl bm bn bo bq br bs bt bw by bz ca cc cd cf cg ch ci ck cl cm cn co cr cu cv cw cx cy cz de dj dk dm do dz ec ee eg eh er es et fi fj fk fm fo fr ga gb gd ge gf gg gh gi gl gm gn gp gq gr gt gu gw gy hk hn hr ht hu id ie il im in io iq ir is it je jm jo jp ke kg kh ki km kn kp kr kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc md me mf mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw mx my mz na nc ne nf ng ni nl no np nr nu nz om pa pe pf pg ph pk pl pm pn pr ps pt pw py qa re ro rs ru rw sa sb sc sd se sg sh si sk sl sm sn so sr ss st sv sx sy sz tc td tg th tj tk tl tm tn to tr tt tv tw tz ua ug us uy uz va vc ve vg vi vn vu wf ws ye yt za zm zw"

var geoRefresh atomic.Int64 // unix seconds of last successful geo-cache fetch

// geoFetchAll downloads every country zone into geoCacheDir (bounded concurrency,
// per-request timeout, failures skipped), then reloads the geo index.
func geoFetchAll() {
	if err := os.MkdirAll(geoCacheDir, 0755); err != nil {
		return
	}
	codes := strings.Fields(isoCodes)
	// ipdeny throttles many concurrent connections from one IP, so keep the
	// concurrency low and retry with a backoff.
	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup
	var n int64
	client := &http.Client{Timeout: 25 * time.Second}
	fetch := func(cc string) []byte {
		for attempt := 0; attempt < 3; attempt++ {
			resp, err := client.Get(ipdenyV4 + "/" + cc + "-aggregated.zone")
			if err == nil {
				if resp.StatusCode == 200 {
					b, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
					resp.Body.Close()
					if len(b) > 0 {
						return b
					}
				} else {
					resp.Body.Close()
					if resp.StatusCode == 404 {
						return nil // ipdeny has no zone for this code
					}
				}
			}
			time.Sleep(time.Duration(400+attempt*600) * time.Millisecond)
		}
		return nil
	}
	for _, cc := range codes {
		wg.Add(1)
		sem <- struct{}{}
		go func(cc string) {
			defer wg.Done()
			defer func() { <-sem }()
			if b := fetch(cc); b != nil {
				if os.WriteFile(geoCacheDir+"/"+cc+".v4", b, 0644) == nil {
					atomic.AddInt64(&n, 1)
				}
			}
		}(cc)
	}
	wg.Wait()
	geoRefresh.Store(time.Now().Unix())
	log.Printf("nftgeo-ui: geo-cache fetched %d/%d country zones", n, len(codes))
	geo.load()
}

func runV(name string, args ...string) string {
	out, _ := run(name, args...)
	return strings.TrimSpace(out)
}

func shortFeed(f string) string {
	for _, k := range []string{"firehol", "spamhaus", "blocklist", "greensnow"} {
		if strings.Contains(f, k) {
			return k
		}
	}
	if len(f) > 24 {
		return f[:24]
	}
	return f
}

// health gathers the status widgets: next scheduled run, last load, feed
// freshness, and the established-connection counter.
func health(ch []Chain) map[string]interface{} {
	h := map[string]interface{}{}
	for _, c := range ch {
		if c.Name == "input" {
			for _, r := range c.Rules {
				if strings.Contains(r.Text, "ct state established") {
					h["established"] = r.Packets
					break
				}
			}
		}
	}
	// systemctl --value prints a formatted timestamp here (not raw microseconds).
	if v := runV("systemctl", "show", "nftgeo.timer", "-p", "NextElapseUSecRealtime", "--value"); v != "" && v != "0" && v != "n/a" {
		h["nextRun"] = v
	}
	if out, err := run("journalctl", "-u", "nftgeo.service", "--no-pager", "-n", "200"); err == nil {
		var last string
		for _, l := range strings.Split(out, "\n") {
			if strings.Contains(l, "loaded "+fam+"/"+table) {
				last = strings.TrimSpace(l)
			}
		}
		if last != "" {
			h["lastRun"] = last
		}
	}
	var feeds []map[string]interface{}
	if ents, err := os.ReadDir(feedsDir); err == nil {
		for _, e := range ents {
			if fi, err := e.Info(); err == nil {
				age := time.Since(fi.ModTime())
				feeds = append(feeds, map[string]interface{}{
					"name": shortFeed(e.Name()), "ageHours": int(age.Hours()), "fresh": age < 26*time.Hour})
			}
		}
	}
	h["feeds"] = feeds
	return h
}

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
	mu    sync.RWMutex
	v4    map[byte][]v4net // first octet -> nets
	when  time.Time
	count int
	ccs   int
}
type v4net struct {
	ip, mask uint32
	cc       string
}

var geo = &geoIndex{v4: map[byte][]v4net{}}

func (g *geoIndex) load() {
	idx := map[byte][]v4net{}
	seen := map[string]bool{}
	total := 0
	// UI geo-cache first (broad coverage wins), then the engine's zone cache.
	for _, dir := range []string{geoCacheDir, zoneDir} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".v4") {
				continue
			}
			cc := strings.TrimSuffix(name, ".v4")
			if seen[cc] {
				continue
			}
			seen[cc] = true
			data, err := os.ReadFile(dir + "/" + name)
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
				idx[ip4[0]] = append(idx[ip4[0]], v4net{be32(ip4), be32(net.IP(n.Mask).To4()), cc})
				total++
			}
		}
	}
	g.mu.Lock()
	g.v4 = idx
	g.when = time.Now()
	g.count = total
	g.ccs = len(seen)
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

func geoStale() bool {
	ents, err := os.ReadDir(geoCacheDir)
	if err != nil || len(ents) < 50 {
		return true
	}
	var newest time.Time
	for _, e := range ents {
		if fi, err := e.Info(); err == nil && fi.ModTime().After(newest) {
			newest = fi.ModTime()
		}
	}
	return time.Since(newest) > 24*time.Hour
}

func be32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// ---- drops from journald ----------------------------------------------------

type Drop struct {
	Time  string `json:"time"`
	Src   string `json:"src"`
	Dst   string `json:"dst"`
	Dport string `json:"dport"`
	Proto string `json:"proto"`
	Dir   string `json:"dir"` // ingress|egress|forward
	CC    string `json:"cc"`
}
type DropsResp struct {
	Enabled     bool           `json:"enabled"`
	Total       int            `json:"total"`
	IngressByCC map[string]int `json:"ingressByCC"`
	EgressByCC  map[string]int `json:"egressByCC"`
	TopPorts    map[string]int `json:"topPorts"`
	Timeline    []int          `json:"timeline"` // last 24h, hourly buckets (oldest first)
	Recent      []Drop         `json:"recent"`
}

var reKV = regexp.MustCompile(`(\w+)=(\S+)`)

func drops(since string) DropsResp {
	resp := DropsResp{IngressByCC: map[string]int{}, EgressByCC: map[string]int{}, TopPorts: map[string]int{}, Timeline: make([]int, 24)}
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
			t := time.UnixMicro(us)
			d.Time = t.UTC().Format(time.RFC3339)
			if ha := int(time.Since(t).Hours()); ha >= 0 && ha < 24 {
				resp.Timeline[23-ha]++
			}
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

// ---- policy (rules.conf) & objects (config) --------------------------------

type PolicyRule struct {
	Num     int    `json:"num"`
	Action  string `json:"action"`
	Dir     string `json:"dir"`
	Proto   string `json:"proto"`
	Port    string `json:"port"`
	Target  string `json:"target"`
	Iface   string `json:"iface"`
	Comment string `json:"comment"`
	File    string `json:"file"`
	Hits    int64  `json:"hits"`
	Matches []Rule `json:"matches"`
}

// sanitize mirrors the engine's sanitize_lower: lowercase, non-alphanumeric runs
// collapsed to '_', edges trimmed - so a target maps to its "g_<name>" set.
func sanitize(s string) string {
	s = strings.ToLower(s)
	var b strings.Builder
	prevU := false
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			prevU = false
		} else if !prevU {
			b.WriteByte('_')
			prevU = true
		}
	}
	return strings.Trim(b.String(), "_")
}

// annotate joins each policy rule to the loaded chain rules that implement it,
// summing their live counters (best-effort: by hook, verdict, port, side, and the
// target's set name).
func annotate(rules []PolicyRule, chs []Chain) {
	byHook := map[string]Chain{}
	for _, c := range chs {
		byHook[c.Name] = c
	}
	for i := range rules {
		r := &rules[i]
		hook := "input"
		switch r.Dir {
		case "out":
			hook = "output"
		case "fwd-in", "fwd-out":
			hook = "forward"
		}
		verdict := "accept"
		if r.Action == "deny" {
			verdict = "drop"
		}
		side := "saddr"
		if r.Dir == "out" || r.Dir == "fwd-out" {
			side = "daddr"
		}
		portTok := ""
		if r.Port != "-" {
			portTok = "dport " + r.Port
		}
		var sets []string
		switch r.Target {
		case "any":
		case "abuse":
			sets = []string{"@abuse4", "@abuse6"}
		default:
			b := sanitize(r.Target)
			sets = []string{"@g_" + b + "4", "@g_" + b + "6"}
		}
		for _, cr := range byHook[hook].Rules {
			if cr.Verdict != verdict {
				continue
			}
			if portTok != "" && !strings.Contains(cr.Text, portTok) {
				continue
			}
			ok := false
			if r.Target == "any" {
				ok = !strings.Contains(cr.Text, "@")
			} else {
				for _, s := range sets {
					if strings.Contains(cr.Text, s) && strings.Contains(cr.Text, side) {
						ok = true
					}
				}
			}
			if ok {
				r.Matches = append(r.Matches, cr)
				r.Hits += cr.Packets
			}
		}
	}
}

func ruleFiles() []string {
	files := []string{rulesFile}
	if ents, err := os.ReadDir(rulesDir); err == nil {
		var ds []string
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".conf") {
				ds = append(ds, e.Name())
			}
		}
		sort.Strings(ds)
		for _, d := range ds {
			files = append(files, rulesDir+"/"+d)
		}
	}
	return files
}

func policy() []PolicyRule {
	var out []PolicyRule
	n := 0
	for _, f := range ruleFiles() {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		base := filepath.Base(f)
		for _, line := range strings.Split(string(data), "\n") {
			comment := ""
			if i := strings.Index(line, "#"); i >= 0 {
				comment = strings.TrimSpace(line[i+1:])
				line = line[:i]
			}
			fields := strings.Fields(line)
			if len(fields) < 5 || (fields[0] != "allow" && fields[0] != "deny") {
				continue
			}
			n++
			pr := PolicyRule{Num: n, Action: fields[0], Dir: fields[1], Proto: fields[2],
				Port: fields[3], Target: fields[4], Comment: comment, File: base}
			for i := 5; i < len(fields)-1; i++ {
				if fields[i] == "on" {
					pr.Iface = fields[i+1]
				}
			}
			out = append(out, pr)
		}
	}
	return out
}

func objects() map[string]interface{} {
	groups := []map[string]string{}
	regions := []map[string]string{}
	var wl, wlh, feeds []string
	data, _ := os.ReadFile(configFile)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		k := strings.TrimSpace(line[:eq])
		v := strings.Trim(strings.TrimSpace(line[eq+1:]), `"`)
		switch {
		case strings.HasPrefix(k, "GROUP_"):
			groups = append(groups, map[string]string{"name": strings.ToLower(k[6:]), "value": v})
		case strings.HasPrefix(k, "REGION_"):
			regions = append(regions, map[string]string{"name": strings.ToLower(k[7:]), "value": v})
		case k == "WHITELIST":
			wl = strings.Fields(v)
		case k == "WHITELIST_HOSTS":
			wlh = strings.Fields(v)
		case k == "ABUSE_FEEDS":
			feeds = strings.Fields(v)
		}
	}
	return map[string]interface{}{"groups": groups, "regions": regions,
		"whitelist": wl, "whitelistHosts": wlh, "feeds": feeds}
}

// ---- per-IP lookup: reverse DNS + RDAP (whois) -----------------------------

func rdapOrg(m map[string]interface{}) string {
	ents, _ := m["entities"].([]interface{})
	for _, e := range ents {
		em, _ := e.(map[string]interface{})
		va, _ := em["vcardArray"].([]interface{})
		if len(va) < 2 {
			continue
		}
		props, _ := va[1].([]interface{})
		for _, p := range props {
			pa, _ := p.([]interface{})
			if len(pa) >= 4 && pa[0] == "fn" {
				if s, ok := pa[3].(string); ok && s != "" {
					return s
				}
			}
		}
	}
	return ""
}

func doLookup(ip string) map[string]interface{} {
	res := map[string]interface{}{"ip": ip}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if names, err := net.DefaultResolver.LookupAddr(ctx, ip); err == nil && len(names) > 0 {
		res["ptr"] = names
	}
	client := &http.Client{Timeout: 6 * time.Second}
	if r, err := client.Get("https://rdap.org/ip/" + url.PathEscape(ip)); err == nil {
		defer r.Body.Close()
		var m map[string]interface{}
		if json.NewDecoder(r.Body).Decode(&m) == nil {
			w := map[string]interface{}{}
			for _, k := range []string{"handle", "name", "country", "type", "startAddress", "endAddress"} {
				if v, ok := m[k]; ok {
					w[k] = v
				}
			}
			if c, ok := m["cidr0_cidrs"].([]interface{}); ok && len(c) > 0 {
				if cm, ok := c[0].(map[string]interface{}); ok {
					w["cidr"] = fmt.Sprintf("%v/%v", cm["v4prefix"], cm["length"])
				}
			}
			if org := rdapOrg(m); org != "" {
				w["org"] = org
			}
			res["rdap"] = w
		}
	}
	return res
}

// ---- http -------------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

// ---- auth: root-minted HMAC token -> HttpOnly session cookie ----------------

var (
	secretFile = env("UI_SECRET_FILE", "/var/lib/nftgeo/ui-secret")
	authSecret []byte
	authOn     bool
	sessionTTL = parseDur(env("UI_SESSION_TTL", "15m"), 15*time.Minute)

	sessMu    sync.Mutex
	sessions  = map[string]*uiSession{}
	usedNonce = map[string]bool{}
)

type uiSession struct {
	mode string
	last time.Time
}

func parseDur(s string, def time.Duration) time.Duration {
	if v, err := time.ParseDuration(s); err == nil {
		return v
	}
	return def
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// loadOrCreateSecret reads (or, as root, creates) the 0600 signing secret. Only a
// process that can read it (root) can mint tokens.
func loadOrCreateSecret() ([]byte, error) {
	if b, err := os.ReadFile(secretFile); err == nil && len(b) >= 16 {
		return b, nil
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	os.MkdirAll(filepath.Dir(secretFile), 0700)
	if err := os.WriteFile(secretFile, b, 0600); err != nil {
		return nil, err
	}
	return b, nil
}

func mintToken(secret []byte, mode string, exp time.Time) string {
	payload := fmt.Sprintf("%s:%d:%s", mode, exp.Unix(), randHex(8))
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	sig := hex.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload + "." + sig))
}

func verifyToken(tok string) (mode, nonce string, ok bool) {
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return "", "", false
	}
	i := strings.LastIndex(string(raw), ".")
	if i < 0 {
		return "", "", false
	}
	payload, sig := string(raw)[:i], string(raw)[i+1:]
	mac := hmac.New(sha256.New, authSecret)
	mac.Write([]byte(payload))
	if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(sig)) {
		return "", "", false
	}
	p := strings.Split(payload, ":")
	if len(p) != 3 {
		return "", "", false
	}
	expUnix, _ := strconv.ParseInt(p[1], 10, 64)
	if time.Now().Unix() > expUnix {
		return "", "", false
	}
	return p[0], p[2], true
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Auth string `json:"auth"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)
	mode, nonce, ok := verifyToken(body.Auth)
	if !ok {
		http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
		return
	}
	sessMu.Lock()
	if mode == "rw" { // full-access bootstrap tokens are single-use
		if usedNonce[nonce] {
			sessMu.Unlock()
			http.Error(w, `{"error":"token already used"}`, http.StatusUnauthorized)
			return
		}
		usedNonce[nonce] = true
	}
	sid := randHex(24)
	sessions[sid] = &uiSession{mode: mode, last: time.Now()}
	sessMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "nftgeo_sess", Value: sid, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]interface{}{"mode": mode})
}

// requireAuth gates an API handler: a valid, non-idle session cookie is required;
// a read-only session may only issue GETs (writes -> 403), ready for phase B.
func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !authOn {
			next(w, r)
			return
		}
		c, err := r.Cookie("nftgeo_sess")
		if err != nil {
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		sessMu.Lock()
		s := sessions[c.Value]
		if s == nil || time.Since(s.last) > sessionTTL {
			delete(sessions, c.Value)
			sessMu.Unlock()
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}
		if s.mode == "ro" && r.Method != http.MethodGet {
			sessMu.Unlock()
			http.Error(w, `{"error":"read-only session"}`, http.StatusForbidden)
			return
		}
		s.last = time.Now()
		mode := s.mode
		sessMu.Unlock()
		w.Header().Set("X-Nftgeo-Mode", mode)
		next(w, r)
	}
}

func sweepSessions() {
	for range time.Tick(time.Minute) {
		sessMu.Lock()
		for id, s := range sessions {
			if time.Since(s.last) > sessionTTL {
				delete(sessions, id)
			}
		}
		sessMu.Unlock()
	}
}

func tokenCmd(args []string) {
	fs := flag.NewFlagSet("token", flag.ExitOnError)
	ro := fs.Bool("ro", false, "long-term read-only token (panel only, no firewall changes)")
	addr := fs.String("addr", "127.0.0.1:8787", "server address for the link")
	ttl := fs.Duration("ttl", 0, "override token validity window")
	fs.Parse(args)
	secret, err := loadOrCreateSecret()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cannot access the signing secret (run as root):", err)
		os.Exit(1)
	}
	mode, exp := "rw", time.Now().Add(10*time.Minute)
	if *ro {
		mode, exp = "ro", time.Now().Add(90*24*time.Hour)
	}
	if *ttl != 0 {
		exp = time.Now().Add(*ttl)
	}
	tok := mintToken(secret, mode, exp)
	fmt.Printf("Open (valid until %s):\n  http://%s/?auth=%s\n", exp.Format("2006-01-02 15:04 MST"), *addr, tok)
	if mode == "ro" {
		fmt.Println("Mode: read-only - long-term panel access, no firewall changes.")
	} else {
		fmt.Printf("Mode: full - one-time link; the session then expires after %s of inactivity.\n", sessionTTL)
	}
}

// ---- draft + commit pipeline (M6B.1) ----------------------------------------
//
// The UI edits a server-side *draft* of rules.conf; the live file is untouched
// until the operator commits. Commit runs the engine's own safe pipeline:
// validate -> plan -> apply --confirm (deadman). Every mutating endpoint below
// is POST/PUT, so requireAuth already restricts them to read-write sessions
// (read-only sessions get 403 on any non-GET). The live firewall never changes
// before an explicit Deploy, and a timed-out deadman auto-restores rules.conf.

var (
	nftgeoBin = env("NFTGEO_BIN", "/usr/local/sbin/nftgeo")
	stateDir  = env("STATE_DIR", "/var/lib/nftgeo")
	groupsDir = env("GROUPS_DIR", "/etc/nftgeo/groups.d")
	sentinel  = env("SENTINEL", filepath.Join(stateDir, ".pending-confirm"))

	// rules.conf staging (M6B.1)
	draftFile  = env("UI_DRAFT_FILE", filepath.Join(stateDir, "ui-draft.rules"))
	backupFile = filepath.Join(stateDir, "ui-commit-backup.rules")

	// objects staging (M6B.2): GROUP_*/REGION_* live in a UI-owned groups.d
	// drop-in, sourced by the engine after config.
	objLiveFile   = filepath.Join(groupsDir, "ui-objects.conf")
	objDraftFile  = filepath.Join(stateDir, "ui-draft.objects")
	objBackupFile = filepath.Join(stateDir, "ui-commit-backup.objects")
)

// A stage is one file the UI drafts and commits: the operator edits `draft`,
// Commit backs up `live`, promotes `draft` -> `live`, and the pipeline can
// restore `live` from `backup` on rollback / deadman / interrupted deploy.
type stage struct{ name, draft, live, backup string }

func stages() []stage {
	return []stage{
		{"rules", draftFile, rulesFile, backupFile},
		{"objects", objDraftFile, objLiveFile, objBackupFile},
	}
}

func (s stage) hasDraft() bool { _, e := os.Stat(s.draft); return e == nil }

func activeStages() []stage {
	var a []stage
	for _, s := range stages() {
		if s.hasDraft() {
			a = append(a, s)
		}
	}
	return a
}

var (
	commitMu sync.Mutex
	pending  struct {
		active   bool
		deadline time.Time
		seconds  int
	}
)

func readFileStr(p string) string { b, _ := os.ReadFile(p); return string(b) }

// diffText returns a unified live->draft diff and the changed-line count.
func diffText(live, draft string) (string, int) {
	if live == draft {
		return "", 0
	}
	ta, _ := os.CreateTemp("", "nftgeo-a-*")
	tb, _ := os.CreateTemp("", "nftgeo-b-*")
	defer os.Remove(ta.Name())
	defer os.Remove(tb.Name())
	ta.WriteString(live)
	ta.Close()
	tb.WriteString(draft)
	tb.Close()
	out, _ := run("diff", "-u", "--label", "live", "--label", "draft", ta.Name(), tb.Name())
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if (strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++")) ||
			(strings.HasPrefix(l, "-") && !strings.HasPrefix(l, "---")) {
			n++
		}
	}
	return out, n
}

// runEnv runs a command with extra environment, capturing stdout+stderr (so the
// engine's "INVALID:" validation messages come through).
func runEnv(extra []string, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), extra...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	os.MkdirAll(filepath.Dir(dst), 0755)
	return os.WriteFile(dst, b, 0644)
}

// backupLive snapshots a stage's live file (an absent live file - e.g. the
// objects drop-in on first use - snapshots as empty, which restores to a
// harmless empty drop-in).
func backupLive(s stage) error {
	b, err := os.ReadFile(s.live)
	if err != nil {
		b = []byte{}
	}
	return os.WriteFile(s.backup, b, 0644)
}

func restoreBackups() {
	for _, s := range stages() {
		if _, e := os.Stat(s.backup); e == nil {
			copyFile(s.backup, s.live)
			os.Remove(s.backup)
		}
	}
}

// previewEnv builds engine env overrides so validate/plan render the *draft*
// state (draft rules + draft objects) without touching any live file. Returns a
// cleanup to remove the temp groups dir.
func previewEnv() ([]string, func()) {
	var envv []string
	cleanup := func() {}
	if _, e := os.Stat(draftFile); e == nil {
		envv = append(envv, "RULES_FILE="+draftFile)
	}
	if _, e := os.Stat(objDraftFile); e == nil {
		tmp, err := os.MkdirTemp("", "nftgeo-gd-*")
		if err == nil {
			if ents, e := os.ReadDir(groupsDir); e == nil {
				for _, en := range ents {
					if strings.HasSuffix(en.Name(), ".conf") && en.Name() != filepath.Base(objLiveFile) {
						if b, e := os.ReadFile(filepath.Join(groupsDir, en.Name())); e == nil {
							os.WriteFile(filepath.Join(tmp, en.Name()), b, 0644)
						}
					}
				}
			}
			if b, e := os.ReadFile(objDraftFile); e == nil {
				os.WriteFile(filepath.Join(tmp, filepath.Base(objLiveFile)), b, 0644)
			}
			envv = append(envv, "GROUPS_DIR="+tmp)
			cleanup = func() { os.RemoveAll(tmp) }
		}
	}
	return envv, cleanup
}

func validateDraft() (string, bool) {
	envv, cl := previewEnv()
	defer cl()
	out, err := runEnv(envv, nftgeoBin, "validate")
	return strings.TrimSpace(out), err == nil
}

// ---- rules draft (M6B.1) ----

func handleDraft(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		live := readFileStr(rulesFile)
		text, exists := live, false
		if b, err := os.ReadFile(draftFile); err == nil {
			text, exists = string(b), true
		}
		diff, changed := "", 0
		if exists {
			diff, changed = diffText(live, text)
		}
		writeJSON(w, map[string]interface{}{"exists": exists, "live": live, "draft": text, "diff": diff, "changed": changed})
	case http.MethodPut:
		body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		if err != nil {
			http.Error(w, `{"error":"read failed"}`, http.StatusBadRequest)
			return
		}
		if err := os.WriteFile(draftFile, body, 0644); err != nil {
			http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
			return
		}
		_, changed := diffText(readFileStr(rulesFile), string(body))
		writeJSON(w, map[string]interface{}{"saved": true, "changed": changed})
	default:
		http.Error(w, `{"error":"method"}`, http.StatusMethodNotAllowed)
	}
}

// handleDraftDiscard drops the entire pending changeset (all stages).
func handleDraftDiscard(w http.ResponseWriter, r *http.Request) {
	for _, s := range stages() {
		os.Remove(s.draft)
	}
	writeJSON(w, map[string]interface{}{"discarded": true})
}

// ---- objects draft (M6B.2) ----

type objEntry struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

var objLineRe = regexp.MustCompile(`^(GROUP|REGION)_([A-Za-z0-9_]+)=(.*)$`)
var objNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
var objMemberRe = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)

func parseObjects(text string) (groups, regions []objEntry) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := objLineRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		val := strings.Trim(strings.TrimSpace(m[3]), `"`)
		e := objEntry{Name: m[2], Members: strings.Fields(val)}
		if m[1] == "GROUP" {
			groups = append(groups, e)
		} else {
			regions = append(regions, e)
		}
	}
	return
}

func serializeObjects(groups, regions []objEntry) string {
	var b strings.Builder
	b.WriteString("# Managed by nftgeo-ui (Objects tab). Do not hand-edit; the panel overwrites this file.\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "GROUP_%s=\"%s\"\n", strings.ToUpper(g.Name), strings.Join(g.Members, " "))
	}
	for _, rg := range regions {
		fmt.Fprintf(&b, "REGION_%s=\"%s\"\n", strings.ToUpper(rg.Name), strings.Join(rg.Members, " "))
	}
	return b.String()
}

// sanitizeObjects rejects anything that isn't a plain name / member token -
// these values are sourced by the shell engine, so metacharacters must not pass.
func sanitizeObjects(lists ...[]objEntry) error {
	seen := map[string]bool{}
	for _, list := range lists {
		for _, e := range list {
			if !objNameRe.MatchString(e.Name) {
				return fmt.Errorf("invalid name %q (use letters, digits, underscore)", e.Name)
			}
			key := strings.ToUpper(e.Name)
			if seen[key] {
				return fmt.Errorf("duplicate name %q", e.Name)
			}
			seen[key] = true
			for _, m := range e.Members {
				if !objMemberRe.MatchString(m) {
					return fmt.Errorf("invalid member %q in %s", m, e.Name)
				}
			}
		}
	}
	return nil
}

func handleObjectsDraft(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		text := readFileStr(objLiveFile)
		_, exists := os.Stat(objDraftFile)
		if exists == nil {
			text = readFileStr(objDraftFile)
		}
		g, rg := parseObjects(text)
		if g == nil {
			g = []objEntry{}
		}
		if rg == nil {
			rg = []objEntry{}
		}
		writeJSON(w, map[string]interface{}{"file": objLiveFile, "hasDraft": exists == nil, "groups": g, "regions": rg})
	case http.MethodPut:
		var req struct {
			Groups  []objEntry `json:"groups"`
			Regions []objEntry `json:"regions"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		if err := sanitizeObjects(req.Groups, req.Regions); err != nil {
			http.Error(w, `{"error":`+strconv.Quote(err.Error())+`}`, http.StatusBadRequest)
			return
		}
		out := serializeObjects(req.Groups, req.Regions)
		if err := os.WriteFile(objDraftFile, []byte(out), 0644); err != nil {
			http.Error(w, `{"error":"cannot write objects draft"}`, http.StatusInternalServerError)
			return
		}
		_, changed := diffText(readFileStr(objLiveFile), out)
		writeJSON(w, map[string]interface{}{"saved": true, "changed": changed})
	default:
		http.Error(w, `{"error":"method"}`, http.StatusMethodNotAllowed)
	}
}

// ---- structured rules draft (M6B.3) ----
//
// Parse rules.conf losslessly into ordered rule entries, each carrying its
// leading trivia (blank/comment lines) so reorder and enable/disable round-trip
// through the file. Body is kept verbatim (field parsing is for display only),
// so these ops never rewrite a rule's own text. Field editing is M6B.4.

// draftRule is one ordered item in rules.conf: a rule (Kind "rule") or a section
// header (Kind "section": a "## Title" comment that groups the rules below it).
type draftRule struct {
	ID       int      `json:"id"`
	Kind     string   `json:"kind"`
	Title    string   `json:"title,omitempty"`
	Disabled bool     `json:"disabled"`
	Action   string   `json:"action"`
	Dir      string   `json:"dir"`
	Proto    string   `json:"proto"`
	Port     string   `json:"port"`
	Target   string   `json:"target"`
	Iface    string   `json:"iface"`
	Name     string   `json:"name"`
	Body     string   `json:"body"`
	Trivia   []string `json:"-"`
	Hits     int64    `json:"hits"`
	Matched  bool     `json:"matched"`
}

var sectionRe = regexp.MustCompile(`^#{2,}\s*(.*?)\s*#*$`)

// ruleFields splits a candidate rule line into fields + trailing comment, and
// reports whether it is a valid allow/deny rule.
func ruleFields(s string) (fields []string, body, comment string, ok bool) {
	body = s
	if i := strings.Index(body, "#"); i >= 0 {
		comment = strings.TrimSpace(body[i+1:])
		body = body[:i]
	}
	body = strings.TrimSpace(body)
	f := strings.Fields(body)
	if len(f) >= 5 && (f[0] == "allow" || f[0] == "deny") {
		return f, body, comment, true
	}
	return nil, "", "", false
}

func mkDraftRule(id int, disabled bool, f []string, body, comment string, trivia []string) *draftRule {
	r := &draftRule{ID: id, Kind: "rule", Disabled: disabled, Body: body, Name: comment, Trivia: trivia,
		Action: f[0], Dir: f[1], Proto: f[2], Port: f[3], Target: f[4]}
	for i := 5; i < len(f)-1; i++ {
		if f[i] == "on" {
			r.Iface = f[i+1]
		}
	}
	return r
}

func parseDraftRules(text string) ([]*draftRule, []string) {
	var rules []*draftRule
	var trivia []string
	id := 0
	for _, raw := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(raw)
		if strings.HasPrefix(trimmed, "##") {
			// "## Title" is a section header (grouping label).
			title := ""
			if m := sectionRe.FindStringSubmatch(trimmed); m != nil {
				title = m[1]
			}
			rules = append(rules, &draftRule{ID: id, Kind: "section", Title: title, Trivia: trivia})
			id++
			trivia = nil
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			// A commented line that parses as a rule is a disabled rule.
			if f, body, comment, ok := ruleFields(strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))); ok {
				rules = append(rules, mkDraftRule(id, true, f, body, comment, trivia))
				id++
				trivia = nil
				continue
			}
		} else if f, body, comment, ok := ruleFields(trimmed); ok {
			rules = append(rules, mkDraftRule(id, false, f, body, comment, trivia))
			id++
			trivia = nil
			continue
		}
		trivia = append(trivia, raw)
	}
	return rules, trivia
}

func serializeDraftRules(rules []*draftRule, tail []string) string {
	var b strings.Builder
	for _, r := range rules {
		for _, t := range r.Trivia {
			b.WriteString(t)
			b.WriteByte('\n')
		}
		if r.Kind == "section" {
			b.WriteString("## " + r.Title + "\n")
			continue
		}
		if r.Disabled {
			b.WriteString("# ")
		}
		b.WriteString(r.Body)
		if r.Name != "" {
			b.WriteString(" # " + r.Name)
		}
		b.WriteByte('\n')
	}
	for _, t := range tail {
		b.WriteString(t)
		b.WriteByte('\n')
	}
	return b.String()
}

func draftRulesText() (string, bool) {
	if b, err := os.ReadFile(draftFile); err == nil {
		return string(b), true
	}
	return readFileStr(rulesFile), false
}

// annotateDraft fills live hit counts for enabled rules (best-effort, via the
// same signature match as the read-only policy view).
func annotateDraft(rules []*draftRule, chs []Chain) {
	var prs []PolicyRule
	var idx []int
	for i, r := range rules {
		if r.Disabled || r.Kind == "section" {
			continue
		}
		prs = append(prs, PolicyRule{Action: r.Action, Dir: r.Dir, Proto: r.Proto, Port: r.Port, Target: r.Target})
		idx = append(idx, i)
	}
	annotate(prs, chs)
	for k, pr := range prs {
		rules[idx[k]].Hits = pr.Hits
		rules[idx[k]].Matched = len(pr.Matches) > 0
	}
}

func writeDraftRules(rules []*draftRule, tail []string) error {
	return os.WriteFile(draftFile, []byte(serializeDraftRules(rules, tail)), 0644)
}

func handleRulesDraft(w http.ResponseWriter, r *http.Request) {
	text, hasDraft := draftRulesText()
	rules, _ := parseDraftRules(text)
	annotateDraft(rules, chains())
	if rules == nil {
		rules = []*draftRule{}
	}
	writeJSON(w, map[string]interface{}{"hasDraft": hasDraft, "rules": rules})
}

func handleRulesReorder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Order []int `json:"order"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	text, _ := draftRulesText()
	rules, tail := parseDraftRules(text)
	if len(req.Order) != len(rules) {
		http.Error(w, `{"error":"order length mismatch"}`, http.StatusBadRequest)
		return
	}
	byID := map[int]*draftRule{}
	for _, rr := range rules {
		byID[rr.ID] = rr
	}
	var nr []*draftRule
	seen := map[int]bool{}
	for _, id := range req.Order {
		rr := byID[id]
		if rr == nil || seen[id] {
			http.Error(w, `{"error":"invalid order"}`, http.StatusBadRequest)
			return
		}
		seen[id] = true
		nr = append(nr, rr)
	}
	if err := writeDraftRules(nr, tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true})
}

func handleRulesToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	text, _ := draftRulesText()
	rules, tail := parseDraftRules(text)
	var found *draftRule
	for _, rr := range rules {
		if rr.ID == req.ID {
			found = rr
		}
	}
	if found == nil || found.Kind == "section" {
		http.Error(w, `{"error":"no such rule"}`, http.StatusBadRequest)
		return
	}
	found.Disabled = !found.Disabled
	if err := writeDraftRules(rules, tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true, "disabled": found.Disabled})
}

// handleRulesSection adds a new section header (no id) or renames one (with id).
func handleRulesSection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID    *int   `json:"id"`
		Title string `json:"title"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	title := sanitizeComment(req.Title)
	if title == "" {
		http.Error(w, `{"error":"section needs a title"}`, http.StatusBadRequest)
		return
	}
	text, _ := draftRulesText()
	rules, tail := parseDraftRules(text)
	if req.ID != nil {
		var found *draftRule
		for _, rr := range rules {
			if rr.ID == *req.ID && rr.Kind == "section" {
				found = rr
			}
		}
		if found == nil {
			http.Error(w, `{"error":"no such section"}`, http.StatusBadRequest)
			return
		}
		found.Title = title
	} else {
		rules = append(rules, &draftRule{ID: -1, Kind: "section", Title: title})
	}
	if err := writeDraftRules(rules, tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true})
}

// ---- templates / building blocks (M6B.7) ----

type ruleTemplate struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Builtin     bool     `json:"builtin"`
	Lines       []string `json:"lines"`
}

var templatesFile = filepath.Join(stateDir, "ui-templates.json")

func builtinTemplates() []ruleTemplate {
	return []ruleTemplate{
		{ID: "abuse-block", Name: "Block abuse feeds", Builtin: true,
			Description: "Drop traffic to and from the AbuseIPDB + feed blocklists.",
			Lines:       []string{"## Abuse", "deny in any - abuse # abuse in", "deny out any - abuse # abuse out"}},
		{ID: "safe-web", Name: "Safe Web Server", Builtin: true,
			Description: "Allow HTTP/HTTPS from anywhere and block known abuse both ways.",
			Lines:       []string{"## Web server", "allow in tcp 80 any # http", "allow in tcp 443 any # https", "deny in any - abuse # abuse in", "deny out any - abuse # abuse out"}},
		{ID: "geo-drop", Name: "Basic Geo-Drop", Builtin: true,
			Description: "Drop all ingress from a few common attack-source countries (edit to taste).",
			Lines:       []string{"## Geo-Drop", "deny in any - cn # geo-drop", "deny in any - ru # geo-drop", "deny in any - kp # geo-drop"}},
	}
}

func loadSavedTemplates() []ruleTemplate {
	var list []ruleTemplate
	if b, err := os.ReadFile(templatesFile); err == nil {
		json.Unmarshal(b, &list)
	}
	return list
}

func saveSavedTemplates(list []ruleTemplate) error {
	b, _ := json.MarshalIndent(list, "", "  ")
	return os.WriteFile(templatesFile, b, 0644)
}

// currentTemplateLines snapshots the draft (or live) rules as clean template
// lines (rule bodies + section headers, without blank/comment trivia).
func currentTemplateLines() []string {
	text, _ := draftRulesText()
	items, _ := parseDraftRules(text)
	var lines []string
	for _, it := range items {
		if it.Kind == "section" {
			lines = append(lines, "## "+it.Title)
			continue
		}
		l := it.Body
		if it.Disabled {
			l = "# " + l
		}
		if it.Name != "" {
			l += " # " + it.Name
		}
		lines = append(lines, l)
	}
	return lines
}

func findTemplate(id string) *ruleTemplate {
	for _, t := range append(builtinTemplates(), loadSavedTemplates()...) {
		if t.ID == id {
			tt := t
			return &tt
		}
	}
	return nil
}

func handleTemplates(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, append(builtinTemplates(), loadSavedTemplates()...))
	case http.MethodPost:
		var req struct{ Name, Description string }
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		name := sanitizeComment(req.Name)
		if name == "" {
			http.Error(w, `{"error":"template needs a name"}`, http.StatusBadRequest)
			return
		}
		lines := currentTemplateLines()
		if len(lines) == 0 {
			http.Error(w, `{"error":"no rules to save"}`, http.StatusBadRequest)
			return
		}
		list := loadSavedTemplates()
		list = append(list, ruleTemplate{
			ID: fmt.Sprintf("saved-%d", time.Now().UnixNano()), Name: name,
			Description: sanitizeComment(req.Description), Lines: lines})
		if err := saveSavedTemplates(list); err != nil {
			http.Error(w, `{"error":"cannot save template"}`, http.StatusInternalServerError)
			return
		}
		writeJSON(w, map[string]interface{}{"saved": true})
	default:
		http.Error(w, `{"error":"method"}`, http.StatusMethodNotAllowed)
	}
}

func handleTemplateDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req)
	list := loadSavedTemplates()
	var keep []ruleTemplate
	for _, t := range list {
		if t.ID != req.ID {
			keep = append(keep, t)
		}
	}
	if err := saveSavedTemplates(keep); err != nil {
		http.Error(w, `{"error":"cannot write templates"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"deleted": true})
}

// handleRulesImport prepends a template's rules/sections to the draft (they still
// need a Commit to deploy).
func handleRulesImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	tpl := findTemplate(req.ID)
	if tpl == nil {
		http.Error(w, `{"error":"no such template"}`, http.StatusBadRequest)
		return
	}
	tplItems, _ := parseDraftRules(strings.Join(tpl.Lines, "\n"))
	text, _ := draftRulesText()
	cur, tail := parseDraftRules(text)
	if err := writeDraftRules(append(tplItems, cur...), tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"imported": true, "rules": len(tplItems)})
}

// ---- rule add / edit / delete (M6B.4) ----

var (
	rulePortRe   = regexp.MustCompile(`^[0-9]+([-,][0-9]+)*$`)
	ruleTargetRe = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)
	ruleIfaceRe  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	ruleProtos   = map[string]bool{"tcp": true, "udp": true, "any": true, "icmp": true, "icmpv6": true}
)

func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "#", "")
	return strings.TrimSpace(s)
}

// buildRuleBody assembles and field-validates a rule line; the engine's own
// validate is still the final gate at preview/deploy.
func buildRuleBody(action, dir, proto, port, target, iface string) (string, error) {
	action, dir = strings.ToLower(strings.TrimSpace(action)), strings.TrimSpace(dir)
	proto, port = strings.ToLower(strings.TrimSpace(proto)), strings.TrimSpace(port)
	target, iface = strings.TrimSpace(target), strings.TrimSpace(iface)
	if action != "allow" && action != "deny" {
		return "", fmt.Errorf("action must be allow or deny")
	}
	switch dir {
	case "in", "out", "fwd-in", "fwd-out":
	default:
		return "", fmt.Errorf("direction must be in / out / fwd-in / fwd-out")
	}
	if !ruleProtos[proto] {
		return "", fmt.Errorf("protocol must be tcp / udp / any / icmp / icmpv6")
	}
	if proto == "any" {
		port = "-"
	}
	if port == "" {
		port = "-"
	}
	if port != "-" && !rulePortRe.MatchString(port) {
		return "", fmt.Errorf("port must be a number, range (n-m) or list (n,m)")
	}
	if !ruleTargetRe.MatchString(target) {
		return "", fmt.Errorf("target: country / region / group / IP / CIDR / any / abuse")
	}
	parts := []string{action, dir, proto, port, target}
	if iface != "" {
		if !ruleIfaceRe.MatchString(iface) {
			return "", fmt.Errorf("invalid interface name")
		}
		parts = append(parts, "on", iface)
	}
	return strings.Join(parts, " "), nil
}

func handleRulesSave(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                                      *int
		Action, Dir, Proto, Port, Target, Iface string
		Name                                    string
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	body, err := buildRuleBody(req.Action, req.Dir, req.Proto, req.Port, req.Target, req.Iface)
	if err != nil {
		http.Error(w, `{"error":`+strconv.Quote(err.Error())+`}`, http.StatusBadRequest)
		return
	}
	name := sanitizeComment(req.Name)
	text, _ := draftRulesText()
	rules, tail := parseDraftRules(text)
	if req.ID != nil {
		var found *draftRule
		for _, rr := range rules {
			if rr.ID == *req.ID {
				found = rr
			}
		}
		if found == nil {
			http.Error(w, `{"error":"no such rule"}`, http.StatusBadRequest)
			return
		}
		found.Body, found.Name = body, name
	} else {
		rules = append(rules, &draftRule{ID: -1, Body: body, Name: name})
	}
	if err := writeDraftRules(rules, tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true})
}

func handleRulesDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID int `json:"id"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	text, _ := draftRulesText()
	rules, tail := parseDraftRules(text)
	idx := -1
	for i, rr := range rules {
		if rr.ID == req.ID {
			idx = i
		}
	}
	if idx < 0 {
		http.Error(w, `{"error":"no such rule"}`, http.StatusBadRequest)
		return
	}
	// Keep the deleted rule's leading comments/blanks with the following rule
	// (or the file tail if it was last), so section headers survive.
	trivia := rules[idx].Trivia
	if idx+1 < len(rules) {
		rules[idx+1].Trivia = append(append([]string{}, trivia...), rules[idx+1].Trivia...)
	} else {
		tail = append(append([]string{}, trivia...), tail...)
	}
	rules = append(rules[:idx], rules[idx+1:]...)
	if err := writeDraftRules(rules, tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"deleted": true})
}

// ---- commit pipeline (all stages) ----

func handleCommitPreview(w http.ResponseWriter, r *http.Request) {
	if len(activeStages()) == 0 {
		http.Error(w, `{"error":"no draft to preview"}`, http.StatusBadRequest)
		return
	}
	msg, ok := validateDraft()
	if !ok {
		writeJSON(w, map[string]interface{}{"valid": false, "message": msg})
		return
	}
	envv, cl := previewEnv()
	defer cl()
	plan, _ := runEnv(envv, nftgeoBin, "plan")
	writeJSON(w, map[string]interface{}{"valid": true, "message": msg, "plan": strings.TrimSpace(plan)})
}

func commitStatus() map[string]interface{} {
	_, serr := os.Stat(sentinel)
	total := 0
	var sts []map[string]interface{}
	for _, s := range stages() {
		if s.hasDraft() {
			_, n := diffText(readFileStr(s.live), readFileStr(s.draft))
			total += n
			sts = append(sts, map[string]interface{}{"name": s.name, "changed": n})
		}
	}
	m := map[string]interface{}{"pending": pending.active, "sentinel": serr == nil, "changed": total, "stages": sts}
	if pending.active {
		m["remaining"] = int(time.Until(pending.deadline).Seconds())
		m["seconds"] = pending.seconds
	}
	return m
}

func handleCommitStatus(w http.ResponseWriter, r *http.Request) {
	commitMu.Lock()
	defer commitMu.Unlock()
	writeJSON(w, commitStatus())
}

func handleCommitApply(w http.ResponseWriter, r *http.Request) {
	commitMu.Lock()
	defer commitMu.Unlock()
	if pending.active {
		http.Error(w, `{"error":"a deploy is already pending; keep or roll it back first"}`, http.StatusConflict)
		return
	}
	if _, err := os.Stat(sentinel); err == nil {
		http.Error(w, `{"error":"a confirm is already pending on the host"}`, http.StatusConflict)
		return
	}
	act := activeStages()
	if len(act) == 0 {
		http.Error(w, `{"error":"no draft to deploy"}`, http.StatusBadRequest)
		return
	}
	// Never deploy an invalid ruleset - validate the draft before touching live.
	if msg, ok := validateDraft(); !ok {
		writeJSON(w, map[string]interface{}{"deployed": false, "valid": false, "message": msg})
		return
	}
	var req struct {
		Seconds int `json:"seconds"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 1<<10)).Decode(&req)
	T := req.Seconds
	if T < 20 || T > 600 {
		T = 90
	}
	// Back up every live file, promote each draft, then apply with the deadman.
	for _, s := range act {
		if err := backupLive(s); err != nil {
			restoreBackups()
			http.Error(w, `{"error":"cannot back up live files"}`, http.StatusInternalServerError)
			return
		}
	}
	for _, s := range act {
		if err := copyFile(s.draft, s.live); err != nil {
			restoreBackups()
			http.Error(w, `{"error":"cannot stage draft to live"}`, http.StatusInternalServerError)
			return
		}
	}
	out, err := run(nftgeoBin, "apply", "--confirm", strconv.Itoa(T))
	if err != nil {
		restoreBackups()
		writeJSON(w, map[string]interface{}{"deployed": false, "message": strings.TrimSpace(out)})
		return
	}
	pending.active = true
	pending.deadline = time.Now().Add(time.Duration(T) * time.Second)
	pending.seconds = T
	go watchDeadman(T)
	writeJSON(w, map[string]interface{}{"deployed": true, "seconds": T, "message": strings.TrimSpace(out)})
}

// watchDeadman restores the live files from backup if the engine deadman fires
// (it reverts the kernel ruleset, but not the on-disk config files).
func watchDeadman(T int) {
	deadline := time.Now().Add(time.Duration(T+4) * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(time.Second)
		if _, err := os.Stat(sentinel); err != nil {
			commitMu.Lock()
			if pending.active {
				restoreBackups()
				pending.active = false
			}
			commitMu.Unlock()
			return
		}
	}
}

func handleCommitKeep(w http.ResponseWriter, r *http.Request) {
	commitMu.Lock()
	defer commitMu.Unlock()
	out, err := run(nftgeoBin, "apply", "--commit")
	if err != nil {
		http.Error(w, `{"error":`+strconv.Quote(strings.TrimSpace(out))+`}`, http.StatusInternalServerError)
		return
	}
	for _, s := range stages() {
		os.Remove(s.draft)
		os.Remove(s.backup)
	}
	pending.active = false
	writeJSON(w, map[string]interface{}{"kept": true, "message": strings.TrimSpace(out)})
}

func handleCommitRollback(w http.ResponseWriter, r *http.Request) {
	commitMu.Lock()
	defer commitMu.Unlock()
	out, _ := run(nftgeoBin, "rollback")
	restoreBackups()
	pending.active = false
	// Keep the drafts so the operator can fix and retry.
	writeJSON(w, map[string]interface{}{"rolledBack": true, "message": strings.TrimSpace(out)})
}

// reconcileCommit recovers a deploy interrupted by a UI restart: leftover
// backups with no pending sentinel mean an apply was never kept, so restore the
// live files from their backups.
func reconcileCommit() {
	if _, err := os.Stat(sentinel); err == nil {
		return // a real confirm is still pending on the host; leave it
	}
	restored := false
	for _, s := range stages() {
		if _, err := os.Stat(s.backup); err == nil {
			copyFile(s.backup, s.live)
			os.Remove(s.backup)
			restored = true
		}
	}
	if restored {
		log.Printf("nftgeo-ui: recovered an unconfirmed deploy - restored live config from backup")
	}
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "token" {
		tokenCmd(os.Args[2:])
		return
	}
	addr := flag.String("addr", "127.0.0.1:8787", "listen address (keep it local)")
	noauth := flag.Bool("noauth", false, "run without auth (trusted localhost only)")
	flag.Parse()

	if !*noauth {
		s, err := loadOrCreateSecret()
		if err != nil {
			log.Fatalf("auth: cannot load/create %s (%v); run as root, or use -noauth for a trusted localhost", secretFile, err)
		}
		authSecret = s
		authOn = true
		go sweepSessions()
	}

	reconcileCommit()

	geo.load()
	go func() {
		for range time.Tick(6 * time.Hour) {
			geo.load()
		}
	}()
	if geoFull != "" {
		go func() {
			if geoStale() {
				geoFetchAll()
			}
			for range time.Tick(24 * time.Hour) {
				geoFetchAll()
			}
		}()
	}

	sub, _ := fs.Sub(assetsFS, "assets")
	http.Handle("/", http.FileServer(http.FS(sub)))

	// token exchange is the only API reachable without a session
	http.HandleFunc("/api/session", handleSession)

	api := func(pattern string, h http.HandlerFunc) { http.HandleFunc(pattern, requireAuth(h)) }

	api("/api/me", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"mode": w.Header().Get("X-Nftgeo-Mode"), "auth": authOn})
	})
	api("/api/status", func(w http.ResponseWriter, r *http.Request) {
		ch := chains()
		writeJSON(w, map[string]interface{}{
			"version": version(),
			"loaded":  tableLoaded(),
			"chains":  ch,
			"health":  health(ch),
			"time":    time.Now().UTC().Format(time.RFC3339),
		})
	})
	api("/api/sets", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, sets())
	})
	api("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		p := policy()
		annotate(p, chains())
		writeJSON(w, p)
	})
	api("/api/objects", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, objects())
	})
	api("/api/geo", func(w http.ResponseWriter, r *http.Request) {
		geo.mu.RLock()
		cnt, ccs, when := geo.count, geo.ccs, geo.when
		geo.mu.RUnlock()
		m := map[string]interface{}{"full": geoFull != "", "cacheDir": geoCacheDir,
			"countries": ccs, "entries": cnt, "indexedAt": when.UTC().Format(time.RFC3339)}
		if ref := geoRefresh.Load(); ref > 0 {
			m["lastRefresh"] = time.Unix(ref, 0).UTC().Format(time.RFC3339)
		}
		writeJSON(w, m)
	})
	api("/api/drops", func(w http.ResponseWriter, r *http.Request) {
		since := r.URL.Query().Get("since")
		if since == "" {
			since = "-24h"
		}
		writeJSON(w, drops(since))
	})
	api("/api/lookup", func(w http.ResponseWriter, r *http.Request) {
		ip := r.URL.Query().Get("ip")
		if net.ParseIP(ip) == nil {
			http.Error(w, `{"error":"invalid ip"}`, http.StatusBadRequest)
			return
		}
		writeJSON(w, doLookup(ip))
	})

	// Draft + commit pipeline (mutations are POST/PUT -> read-write sessions only).
	api("/api/draft", handleDraft)
	api("/api/objects/draft", handleObjectsDraft)
	api("/api/rules/draft", handleRulesDraft)
	api("/api/rules/draft/reorder", handleRulesReorder)
	api("/api/rules/draft/toggle", handleRulesToggle)
	api("/api/rules/draft/save", handleRulesSave)
	api("/api/rules/draft/delete", handleRulesDelete)
	api("/api/rules/draft/section", handleRulesSection)
	api("/api/rules/draft/import", handleRulesImport)
	api("/api/templates", handleTemplates)
	api("/api/templates/delete", handleTemplateDelete)
	api("/api/draft/discard", handleDraftDiscard)
	api("/api/commit/preview", handleCommitPreview)
	api("/api/commit/status", handleCommitStatus)
	api("/api/commit/apply", handleCommitApply)
	api("/api/commit/keep", handleCommitKeep)
	api("/api/commit/rollback", handleCommitRollback)

	mode := "auth on"
	if !authOn {
		mode = "AUTH OFF"
	}
	log.Printf("nftgeo-ui: serving on http://%s (%s)", *addr, mode)
	log.Fatal(http.ListenAndServe(*addr, nil))
}
