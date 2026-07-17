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
	"bufio"
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
	"math/bits"
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
	fam                = env("TABLE_FAMILY", "inet")
	table              = env("TABLE_NAME", "nftgeo")
	zoneDir            = env("ZONE_DIR", "/var/lib/nftgeo/zones")
	engine             = env("NFTGEO_UPDATE", "/usr/sbin/nftgeo-update")
	configFile         = env("CONFIG_FILE", "/etc/nftgeo/config")
	rulesFile          = env("RULES_FILE", "/etc/nftgeo/rules.conf")
	rulesDir           = env("RULES_DIR", "/etc/nftgeo/rules.d")
	ingressFile        = env("INGRESS_FILE", "/etc/nftgeo/ingress.conf")
	ingressDir         = env("INGRESS_DIR", "/etc/nftgeo/ingress.d")
	whitelistFile      = env("WHITELIST_FILE", "/etc/nftgeo/whitelist.conf")
	whitelistHostsFile = env("WHITELIST_HOSTS_FILE", "/etc/nftgeo/whitelist-hosts.conf")
	feedsDir           = env("ABUSE_FEEDS_CACHE_DIR", "/var/lib/nftgeo/feeds")
	// Optional full offline geo dataset (GEO_FULL=1): fetch every ipdeny country
	// zone into a UI-owned cache so the drop map covers all sources.
	geoFull     = env("GEO_FULL", "")
	geoCacheDir = env("GEO_CACHE_DIR", "/var/lib/nftgeo/ui-geo")
	ipdenyV4    = env("IPDENY_V4_URL", "https://www.ipdeny.com/ipblocks/data/aggregated")
	ipdenyV6    = env("IPDENY_V6_URL", "https://www.ipdeny.com/ipv6/ipaddresses/aggregated")
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
	fetch := func(cc string, suffix string) []byte {
		url := ipdenyV4 + "/" + cc + "-aggregated.zone"
		if suffix == "v6" {
			url = ipdenyV6 + "/" + cc + "-aggregated.zone"
		}
		for attempt := 0; attempt < 3; attempt++ {
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				return nil
			}
			req.Header.Set("User-Agent", "nftgeo-ui/geo-cache")
			resp, err := client.Do(req)
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
			if b := fetch(cc, "v4"); b != nil {
				if os.WriteFile(geoCacheDir+"/"+cc+".v4", b, 0644) == nil {
					atomic.AddInt64(&n, 1)
				}
			}
			if b := fetch(cc, "v6"); b != nil {
				if os.WriteFile(geoCacheDir+"/"+cc+".v6", b, 0644) == nil {
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

// shortFeed names an unlabeled feed from its cache filename (the URL with every
// non-alphanumeric char replaced by '_'). It prefers a recognizable provider
// token; "blocklist" is deliberately not one - it is a substring of many hosts
// (e.g. blocklist.greensnow.co) and would shadow the real name. UI-added feeds
// are labeled by the operator instead (see feedLabels).
func shortFeed(f string) string {
	for _, k := range []string{"abuseipdb", "greensnow", "firehol", "spamhaus", "emergingthreats", "dshield", "talos", "blocklist_de"} {
		if strings.Contains(f, k) {
			return strings.ReplaceAll(k, "_", ".")
		}
	}
	s := strings.TrimPrefix(f, "https___")
	s = strings.TrimPrefix(s, "http___")
	if len(s) > 24 {
		s = s[:24]
	}
	return s
}

// sanitizeFeedURL mirrors the engine's cache-file naming (tr -c 'A-Za-z0-9' '_'),
// so a configured feed URL can be matched to its cached file on disk.
func sanitizeFeedURL(u string) string {
	return strings.Map(func(r rune) rune {
		if (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			return r
		}
		return '_'
	}, u)
}

// feedLabels maps each UI-configured feed's cache-file name to the label the
// operator gave it, so abuseSources shows "GREENSNOW" instead of guessing a
// name from the URL.
var (
	feedLabelsCache   map[string]string
	feedLabelsModTime time.Time
	feedLabelsMu      sync.RWMutex
)

func feedLabels() map[string]string {
	fi, err := os.Stat(objLiveFile)
	if err != nil {
		return map[string]string{}
	}
	mod := fi.ModTime()

	feedLabelsMu.RLock()
	if feedLabelsCache != nil && feedLabelsModTime.Equal(mod) {
		m := feedLabelsCache
		feedLabelsMu.RUnlock()
		return m
	}
	feedLabelsMu.RUnlock()

	feedLabelsMu.Lock()
	defer feedLabelsMu.Unlock()
	if feedLabelsCache != nil && feedLabelsModTime.Equal(mod) {
		return feedLabelsCache
	}

	m := map[string]string{}
	b, err := os.ReadFile(objLiveFile)
	if err != nil {
		return m
	}
	_, _, _, _, _, _, feeds := parseObjects(string(b))
	for _, fd := range feeds {
		for _, u := range fd.Members {
			m[sanitizeFeedURL(u)] = fd.Name
		}
	}
	feedLabelsCache = m
	feedLabelsModTime = mod
	return m
}

// runStatus reads the status.json file written by the engine after each run.
// It reports abuse API key state, fetch timestamps, and collected warnings.
// Returns nil if the file is missing (e.g. first boot before the service runs).
func runStatus() map[string]interface{} {
	b, err := os.ReadFile(filepath.Join(stateDir, "status.json"))
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil
	}
	return m
}

// setAbuseIPDBKey writes (or replaces) ABUSEIPDB_API_KEY in the config file.
// The engine reads it on the next run. Empty string clears the key.
func setAbuseIPDBKey(key string) error {
	for _, c := range key {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return fmt.Errorf("invalid API key format: must be alphanumeric")
		}
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "ABUSEIPDB_API_KEY=") {
			lines[i] = "ABUSEIPDB_API_KEY=\"" + key + "\""
			found = true
			break
		}
	}
	if !found {
		// Insert before the first non-comment line, or at the top if none.
		insertAt := 0
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				insertAt = i
				break
			}
			insertAt = i + 1
		}
		lines = append(lines[:insertAt], append([]string{"ABUSEIPDB_API_KEY=\"" + key + "\""}, lines[insertAt:]...)...)
	}
	return os.WriteFile(configFile, []byte(strings.Join(lines, "\n")), 0600)
}

// configValue returns the (unquoted) value of KEY= from the config file, or "".
func configValue(key string) string {
	data, _ := os.ReadFile(configFile)
	for _, line := range strings.Split(string(data), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, key+"=") {
			return strings.Trim(strings.TrimSpace(t[len(key)+1:]), `"`)
		}
	}
	return ""
}

// setConfigValue writes (or replaces) KEY="val" in the config file.
func setConfigValue(key, val string) error {
	if strings.ContainsAny(val, "\"\n\r$`\\;") {
		return fmt.Errorf("invalid characters in config value")
	}

	data, err := os.ReadFile(configFile)
	if err != nil {
		return err
	}
	lines := strings.Split(string(data), "\n")
	repl := key + "=\"" + val + "\""
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), key+"=") {
			lines[i] = repl
			return os.WriteFile(configFile, []byte(strings.Join(lines, "\n")), 0600)
		}
	}
	lines = append(lines, repl)
	return os.WriteFile(configFile, []byte(strings.Join(lines, "\n")), 0600)
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
	// The abuse blocklist is fed by AbuseIPDB (when configured/retained) plus any
	// ABUSE_FEEDS netsets; abuseSources() covers both, so the dashboard widget
	// matches the Reference tab instead of silently omitting AbuseIPDB.
	h["feeds"] = abuseSources()
	h["abuseLoaded"] = abuseLoadedCount()
	h["status"] = runStatus()
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
	// List one chain, not the whole table: `list table` also dumps every set's
	// elements, which is pathologically slow with a large abuse set — and this
	// runs on every dashboard refresh.
	_, err := run("nft", "list", "chain", fam, table, "input")
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

// reChainPolicy matches the default policy in a chain header, e.g.
// "type filter hook input priority -100; policy accept;".
var reChainPolicy = regexp.MustCompile(`policy (accept|drop)`)

// chainPolicies reports each managed chain's default policy — the verdict for a
// packet that matched no rule. input follows DEFAULT_INPUT; output/forward are
// accept. Returns hook -> "accept"|"drop".
func chainPolicies() map[string]string {
	out := map[string]string{}
	for _, hook := range []string{"input", "output", "forward"} {
		txt, err := run("nft", "list", "chain", fam, table, hook)
		if err != nil {
			continue
		}
		if m := reChainPolicy.FindStringSubmatch(txt); m != nil {
			out[hook] = m[1]
		}
	}
	return out
}

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
	// `list sets` returns set declarations (name/type) only — no elements — so it
	// never serialises a huge abuse set. (`list table` dumps every element.)
	out, err := run("nft", "-j", "list", "sets", fam, table)
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
	// Never enumerate the abuse sets: they can hold millions of elements and
	// listing them is what melted the dashboard. -1 means "not counted" (the UI
	// shows the feed-based count instead). Other sets (whitelist/geo/throttle)
	// are small and safe to count.
	if strings.HasPrefix(name, "abuse") {
		return -1
	}
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
	v4    map[byte][]v4net    // first octet -> nets
	v6    map[[2]byte][]v6net // first two bytes -> nets
	when  time.Time
	count int
	ccs   int
}
type v4net struct {
	ip, mask uint32
	cc       string
}
type v6net struct {
	ip   [16]byte
	mask [16]byte
	cc   string
}

var geo = &geoIndex{v4: map[byte][]v4net{}, v6: map[[2]byte][]v6net{}}

func (g *geoIndex) load() {
	idx := map[byte][]v4net{}
	idx6 := map[[2]byte][]v6net{}
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
			isV4 := strings.HasSuffix(name, ".v4")
			isV6 := strings.HasSuffix(name, ".v6")
			if !isV4 && !isV6 {
				continue
			}
			cc := strings.TrimSuffix(name, ".v4")
			cc = strings.TrimSuffix(cc, ".v6")
			if seen[cc] {
				continue
			}
			seen[cc] = true
			f, err := os.Open(dir + "/" + name)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line == "" {
					continue
				}
				_, n, err := net.ParseCIDR(line)
				if err != nil {
					continue
				}
				if isV4 {
					ip4 := n.IP.To4()
					if ip4 == nil {
						continue
					}
					idx[ip4[0]] = append(idx[ip4[0]], v4net{be32(ip4), be32(net.IP(n.Mask).To4()), cc})
					total++
				} else {
					ip6 := n.IP.To16()
					if ip6 == nil {
						continue
					}
					mask6 := net.IP(n.Mask).To16()
					if mask6 == nil {
						continue
					}
					var v6ip, v6mask [16]byte
					copy(v6ip[:], ip6)
					copy(v6mask[:], mask6)
					key := [2]byte{ip6[0], ip6[1]}
					idx6[key] = append(idx6[key], v6net{v6ip, v6mask, cc})
					total++
				}
			}
			f.Close()
		}
	}
	g.mu.Lock()
	g.v4 = idx
	g.v6 = idx6
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
	if ip4 != nil {
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
	// IPv6 lookup
	ip6 := ip.To16()
	if ip6 == nil {
		return ""
	}
	key := [2]byte{ip6[0], ip6[1]}
	g.mu.RLock()
	defer g.mu.RUnlock()
	best, bestMask := "", 0
	for _, n := range g.v6[key] {
		match := true
		prefixLen := 0
		for i := 0; i < 16; i++ {
			if n.mask[i] == 0 {
				break
			}
			if (ip6[i] & n.mask[i]) != n.ip[i] {
				match = false
				break
			}
			prefixLen += bits.LeadingZeros8(n.mask[i])
		}
		if match && prefixLen >= bestMask {
			best, bestMask = n.cc, prefixLen
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
	Time    string `json:"time"`
	Src     string `json:"src"`
	Dst     string `json:"dst"`
	Dport   string `json:"dport"`
	Proto   string `json:"proto"`
	Dir     string `json:"dir"` // ingress|egress|forward
	CC      string `json:"cc"`
	Reason  string `json:"reason"`  // which rule matched: abuse|geo|deny|default-deny or a rule name
	Verdict string `json:"verdict"` // accept|drop (per-rule connection logging)
}
type DropsResp struct {
	Enabled     bool           `json:"enabled"`
	Container   bool           `json:"container"` // in an LXC/container: kernel log not visible
	Nflog       bool           `json:"nflog"`     // drops sourced from the NFLOG listener
	Total       int            `json:"total"`
	IngressByCC map[string]int `json:"ingressByCC"`
	EgressByCC  map[string]int `json:"egressByCC"`
	TopPorts    map[string]int `json:"topPorts"`
	Timeline    []int          `json:"timeline"` // last 24h, hourly buckets (oldest first)
	Recent      []Drop         `json:"recent"`
	RecentTotal int            `json:"recentTotal"`
	HasMore     bool           `json:"hasMore"`
}

const (
	defaultRecentLogLimit = 200
	maxRecentLogLimit     = 5000
)

// kernelLogHidden reports whether nftables `log` output can't reach this
// process. In an LXC/OpenVZ container the netfilter `log` target writes to the
// host's kernel ring buffer, which the container cannot read (`journalctl -k`
// is empty, `dmesg` is denied) — so LOG_DROPS and per-rule `log` produce drops
// but no readable log lines, and the drop map/stats stay empty. Detected once.
var kernelLogHiddenOnce struct {
	sync.Once
	val bool
}

func kernelLogHidden() bool {
	kernelLogHiddenOnce.Do(func() {
		out, err := run("systemd-detect-virt", "--container")
		v := strings.TrimSpace(out)
		// exits 0 with the container type, or non-zero/"none" on bare metal/VM.
		kernelLogHiddenOnce.val = err == nil && v != "" && v != "none"
	})
	return kernelLogHiddenOnce.val
}

var reKV = regexp.MustCompile(`(\w+)=(\S+)`)

// The log prefix is "nftgeo-<drop|accept>:<label>" where <label> is the rule's
// name or a policy category; capture the verdict and label up to the nft "KEY="
// fields (labels may contain spaces). accept lines come from per-rule logging.
var reReason = regexp.MustCompile(`nftgeo-(drop|accept):(.+?)\s+(?:IN|OUT|MAC|PHYSIN|PHYSOUT|SRC|DST)=`)

// drops builds the dashboard's 24h drop summary. Records come from the NFLOG
// listener when it's active (works in containers), else from the kernel log via
// journalctl.
func drops(since string) DropsResp {
	return dropsPage(since, 0, defaultRecentLogLimit)
}

// dropsPage returns one bounded page of the newest matching log records while
// retaining the complete 24-hour aggregates used by the dashboard.
func dropsPage(since string, offset, limit int) DropsResp {
	if offset < 0 {
		offset = 0
	}
	if limit <= 0 {
		limit = defaultRecentLogLimit
	}
	if limit > maxRecentLogLimit {
		limit = maxRecentLogLimit
	}
	var records []Drop
	if nflogActive() {
		records = nflogDropsSince(since)
	} else {
		records = collectJournalDrops(since)
	}
	resp := aggregateDropsAll(records)
	backfillFromStatsLimit(&resp, time.Now(), offset+limit)
	pageRecent(&resp, offset, limit)
	resp.Enabled = logDropsOn()
	resp.Container = kernelLogHidden()
	resp.Nflog = nflogActive()
	return resp
}

// aggregateDrops turns parsed drop/accept records (Dir/CC/Verdict/Time already
// set) into the dashboard summary: totals, per-country, top ports, the 24h
// timeline, and the recent list. accept records show in Recent but do not feed
// the drop analytics.
func aggregateDrops(records []Drop) DropsResp {
	resp := aggregateDropsAll(records)
	pageRecent(&resp, 0, defaultRecentLogLimit)
	return resp
}

func aggregateDropsAll(records []Drop) DropsResp {
	resp := DropsResp{IngressByCC: map[string]int{}, EgressByCC: map[string]int{}, TopPorts: map[string]int{}, Timeline: make([]int, 24)}
	for _, d := range records {
		drop := d.Verdict == "drop"
		if t, e := time.Parse(time.RFC3339, d.Time); e == nil {
			if ha := int(time.Since(t).Hours()); drop && ha >= 0 && ha < 24 {
				resp.Timeline[23-ha]++
			}
		}
		switch d.Dir {
		case "ingress":
			if drop && d.CC != "" {
				resp.IngressByCC[d.CC]++
			}
		case "egress":
			if drop && d.CC != "" {
				resp.EgressByCC[d.CC]++
			}
		}
		if drop {
			if d.Dport != "" {
				resp.TopPorts[d.Dport]++
			}
			resp.Total++
		}
		resp.Recent = append(resp.Recent, d)
	}
	sort.Slice(resp.Recent, func(i, j int) bool { return resp.Recent[i].Time > resp.Recent[j].Time })
	return resp
}

func pageRecent(resp *DropsResp, offset, limit int) {
	resp.RecentTotal = len(resp.Recent)
	if offset >= resp.RecentTotal {
		resp.Recent = nil
		resp.HasMore = false
		return
	}
	end := offset + limit
	if end > resp.RecentTotal {
		end = resp.RecentTotal
	}
	resp.Recent = resp.Recent[offset:end]
	resp.HasMore = end < resp.RecentTotal
}

// collectJournalDrops parses nftgeo log lines from the kernel log (journalctl),
// setting each record's direction, country, verdict, and timestamp.
func collectJournalDrops(since string) []Drop {
	var out []Drop
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "journalctl", "-k", "-o", "json", "--no-pager", "--since", since)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return out
	}
	if err := cmd.Start(); err != nil {
		return out
	}
	defer cmd.Wait()
	defer stdout.Close()

	scanner := bufio.NewScanner(stdout)
	// Kernel log lines in journalctl JSON can sometimes be long, give it a 1MB buffer
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "nftgeo-drop") && !strings.Contains(line, "nftgeo-accept") {
			continue
		}
		var rec struct {
			Msg string `json:"MESSAGE"`
			TS  string `json:"__REALTIME_TIMESTAMP"`
		}
		if json.Unmarshal([]byte(line), &rec) != nil ||
			(!strings.Contains(rec.Msg, "nftgeo-drop") && !strings.Contains(rec.Msg, "nftgeo-accept")) {
			continue
		}
		f := map[string]string{}
		for _, m := range reKV.FindAllStringSubmatch(rec.Msg, -1) {
			f[m[1]] = m[2]
		}
		d := Drop{Src: f["SRC"], Dst: f["DST"], Dport: f["DPT"], Proto: f["PROTO"], Verdict: "drop"}
		if m := reReason.FindStringSubmatch(rec.Msg); m != nil {
			d.Verdict = m[1]
			d.Reason = m[2]
		}
		if us, e := strconv.ParseInt(rec.TS, 10, 64); e == nil {
			d.Time = time.UnixMicro(us).UTC().Format(time.RFC3339)
		}
		in, out2 := f["IN"] != "", f["OUT"] != ""
		switch {
		case in && !out2:
			d.Dir = "ingress"
			d.CC = geo.lookup(d.Src)
		case out2 && !in:
			d.Dir = "egress"
			d.CC = geo.lookup(d.Dst)
		default:
			d.Dir = "forward"
			d.CC = geo.lookup(d.Src)
		}
		out = append(out, d)
	}
	return out
}

func logDropsOn() bool {
	// A cheap heuristic: LOG_DROPS emits "log prefix" rules into the ruleset.
	out, _ := run("nft", "list", "table", fam, table)
	return strings.Contains(out, `log prefix "nftgeo-drop`)
}

// ---- policy (rules.conf) & objects (config) --------------------------------

type PolicyRule struct {
	Num     int    `json:"num"`
	Kind    string `json:"kind,omitempty"` // "" (filter) | "zone" | "nat"
	Action  string `json:"action"`
	Dir     string `json:"dir"`
	Proto   string `json:"proto"`
	Port    string `json:"port"`
	Target  string `json:"target"`
	Iface   string `json:"iface"`
	Src     string `json:"src,omitempty"`  // zone: source zone
	Dst     string `json:"dst,omitempty"`  // zone: destination zone
	Geo     string `json:"geo,omitempty"`  // zone: optional "from <geo>"
	Text    string `json:"text,omitempty"` // nat: verbatim rule text
	Comment string `json:"comment"`
	File    string `json:"file"`
	Hits    int64  `json:"hits"`
	Matched bool   `json:"matched"`
}

// ruleKind classifies a rules.conf line's fields into a policy-table row kind.
// NAT (masquerade/snat/dnat) and inter-zone ("<z> -> <z>") rules are not classic
// filter rules and must not be parsed into the action/dir/proto/port slots.
func ruleKind(f []string) string {
	if len(f) == 0 {
		return ""
	}
	switch f[0] {
	case "masquerade", "snat", "dnat":
		return "nat"
	case "throttle":
		return "throttle"
	case "synproxy":
		return "synproxy"
	case "accept", "drop": // ingress hook rule: <accept|drop> <target> [proto] [port] [log]
		return "ingress"
	case "allow", "deny":
		for _, t := range f {
			if t == "->" {
				return "zone"
			}
		}
		return "filter"
	}
	return ""
}

func isProtoTok(s string) bool {
	switch s {
	case "tcp", "udp", "sctp", "all", "any", "icmp", "icmpv6", "esp", "ah", "gre":
		return true
	}
	return false
}

// ruleComment reproduces the "nftgeo:<line>" tag the engine stamps on every rule
// it generates, built from the same raw rules.conf fields - so counters map
// exactly (service ports, interfaces, multi-port sets and all).
func ruleComment(action, dir, proto, port, target, iface string) string {
	c := action + " " + dir + " " + proto + " " + port + " " + target
	if iface != "" && iface != "-" {
		c += " on " + iface
	}
	return "nftgeo:" + c
}

// ruleCounters reads the live ruleset as JSON and sums packet counters per
// "nftgeo:" comment (a rule can emit several nft rules - v4/v6, proto buckets -
// all sharing the source comment).
func ruleCounters() map[string]int64 {
	m := map[string]int64{}
	// Per-chain, not `-j list table` (which also serialises every set element —
	// pathological with a large abuse set). Rule counters live in the chains.
	for _, hook := range []string{"input", "output", "forward"} {
		out, err := run("nft", "-j", "list", "chain", fam, table, hook)
		if err != nil {
			continue
		}
		ruleCountersInto(m, out)
	}
	return m
}

func ruleCountersInto(m map[string]int64, out string) {
	var doc struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if json.Unmarshal([]byte(out), &doc) != nil {
		return
	}
	for _, item := range doc.Nftables {
		raw, ok := item["rule"]
		if !ok {
			continue
		}
		var r struct {
			Comment string                       `json:"comment"`
			Expr    []map[string]json.RawMessage `json:"expr"`
		}
		if json.Unmarshal(raw, &r) != nil || !strings.HasPrefix(r.Comment, "nftgeo:") {
			continue
		}
		for _, e := range r.Expr {
			if c, ok := e["counter"]; ok {
				var ctr struct {
					Packets int64 `json:"packets"`
				}
				if json.Unmarshal(c, &ctr) == nil {
					m[r.Comment] += ctr.Packets
				}
			}
		}
	}
}

// baselineCounters reads the implicit rules the engine puts at the top of every
// chain - the ones with no "nftgeo:" comment, so ruleCounters skips them, yet
// where most accepted traffic actually lands: established/related and whitelist
// accepts (this is where an allowed, whitelisted, or already-open connection is
// counted, e.g. your own SSH), plus the invalid-state drop. Surfaced so the UI
// can explain why an "allow" rule's own hit count stays low.
func baselineCounters() map[string]map[string]int64 {
	out := map[string]map[string]int64{}
	// -t (terse) skips printing set elements, making a single table dump fast
	// instead of doing N+1 separate execs for each hook.
	txt, err := run("nft", "-t", "list", "table", fam, table)
	if err != nil {
		return out
	}

	var curChain string
	for _, ln := range strings.Split(txt, "\n") {
		t := strings.TrimSpace(ln)

		if strings.HasPrefix(t, "chain ") {
			parts := strings.Fields(t)
			if len(parts) >= 2 {
				curChain = parts[1]
			}
			continue
		}

		if curChain != "input" && curChain != "output" && curChain != "forward" {
			continue
		}

		m := reCounter.FindStringSubmatch(t)
		if m == nil {
			continue
		}

		if out[curChain] == nil {
			out[curChain] = map[string]int64{}
		}
		cur := out[curChain]

		n, _ := strconv.ParseInt(m[1], 10, 64)
		switch {
		case strings.Contains(t, "established,related") && strings.HasSuffix(t, "accept"):
			cur["established"] += n
		case strings.Contains(t, "@whitelist") && strings.HasSuffix(t, "accept"):
			cur["whitelist"] += n
		case strings.Contains(t, "ct state invalid") && strings.HasSuffix(t, "drop"):
			cur["invalid"] += n
		}
	}

	// ensure expected hooks always have at least an empty map
	// so the caller doesn't need to check for nil maps if they iterate specific hooks
	for _, hook := range []string{"input", "output", "forward"} {
		if out[hook] == nil {
			out[hook] = map[string]int64{}
		}
	}

	return out
}

// annotate sets each rule's live hit count by matching the engine's per-rule
// comment against the counter map (from ruleCounters) - exact, not a heuristic.
func annotate(rules []PolicyRule, ctr map[string]int64) {
	for i := range rules {
		r := &rules[i]
		if h, ok := ctr[ruleComment(r.Action, r.Dir, r.Proto, r.Port, r.Target, r.Iface)]; ok {
			r.Hits = h
			r.Matched = true
		}
	}
}

// ---- alerts (M6C.3) --------------------------------------------------------

type Alert struct {
	Level string `json:"level"` // "crit" | "warn"
	Kind  string `json:"kind"`  // "not-loaded" | "feed-stale" | "drop-spike"
	Msg   string `json:"msg"`
}

const (
	spikeFloor  = 200 // ignore anything below this many drops/hour
	spikeFactor = 3   // ...and require >= 3x the baseline
)

// detectSpike inspects 24 hourly buckets (oldest first; index 23 = current,
// still-filling hour). It judges index 22 (last COMPLETE hour) against the
// median of indices 0..21. Returns spike?, that hour's count, and the baseline.
func detectSpike(timeline []int) (bool, int, int) {
	if len(timeline) < 23 {
		return false, 0, 0
	}
	last := timeline[22]
	if last < spikeFloor {
		return false, 0, 0
	}
	// median of indices 0..21 (the 22 full hours before the last complete hour)
	prior := make([]int, 22)
	copy(prior, timeline[:22])
	sort.Ints(prior)
	baseline := prior[len(prior)/2] // median
	if baseline == 0 {
		// no baseline traffic at all — spike only if last hour is very high
		return last >= spikeFloor*5, last, 0
	}
	return last >= baseline*spikeFactor, last, baseline
}

// buildAlerts is pure (no I/O) so it's unit-testable.
func buildAlerts(loaded bool, feeds []map[string]interface{}, timeline []int) []Alert {
	var out []Alert
	if !loaded {
		out = append(out, Alert{Level: "crit", Kind: "not-loaded",
			Msg: "Firewall table not loaded — nftgeo ruleset is not active."})
	}
	for _, f := range feeds {
		if fresh, _ := f["fresh"].(bool); !fresh {
			name, _ := f["name"].(string)
			ageH, _ := f["ageHours"].(int)
			out = append(out, Alert{Level: "warn", Kind: "feed-stale",
				Msg: fmt.Sprintf("Feed %s is stale (%dh old).", name, ageH)})
		}
	}
	if sp, n, bl := detectSpike(timeline); sp {
		out = append(out, Alert{Level: "warn", Kind: "drop-spike",
			Msg: fmt.Sprintf("Drop spike: %d drops in the last hour (baseline ~%d/h).", n, bl)})
	}
	return out
}

// abuseLoadStatus reports progress of a paced (batched) abuse-set load, written
// by the engine to STATE_DIR/abuse-load.progress ("<loaded> <total> <ts>" while
// running, "done <total> <ts>" when finished).
func abuseLoadStatus() map[string]interface{} {
	b, err := os.ReadFile(filepath.Join(stateDir, "abuse-load.progress"))
	if err != nil {
		return map[string]interface{}{"active": false}
	}
	f := strings.Fields(strings.TrimSpace(string(b)))
	if len(f) < 3 || f[0] == "done" {
		return map[string]interface{}{"active": false}
	}
	ts, _ := strconv.ParseInt(f[2], 10, 64)
	if time.Now().Unix()-ts > 300 { // stale: the loader died
		return map[string]interface{}{"active": false}
	}
	loaded, _ := strconv.ParseInt(f[0], 10, 64)
	total, _ := strconv.ParseInt(f[1], 10, 64)
	pct := 0
	if total > 0 {
		pct = int(loaded * 100 / total)
	}
	return map[string]interface{}{"active": true, "loaded": loaded, "total": total, "pct": pct}
}

// ---- in-memory stats store (M6C.4) -----------------------------------------
// Keeps drop events in RAM for fast top-IP queries with time-range filtering.
// Dumps to disk (JSON) only when new drops arrive, so stats survive restarts.
// Capped at maxStatsEntries — oldest entries evicted first.

const maxStatsEntries = 500000 // ~40 MB of drop events; oldest evicted first

type statsEntry struct {
	Ts     int64  `json:"ts"` // unix timestamp
	Src    string `json:"src"`
	CC     string `json:"cc"`
	Port   string `json:"port"`
	Reason string `json:"reason"`
}

var (
	statsMu   sync.Mutex
	statsData []statsEntry
	statsFile = filepath.Join(stateDir, "ui-stats.json")
	// High-water-mark of the newest drop ingested so far. ingestDropsLog polls
	// the last hour every few minutes; without this it would re-ingest (and thus
	// multiply-count) the same events on every tick. Written only by the single
	// ingest goroutine (and loadStats before it starts), so no lock is needed.
	lastIngestTs int64
)

// recordStats appends new drops, keeping at most maxStatsEntries (newest wins).
func recordStats(entries []statsEntry) {
	if len(entries) == 0 {
		return
	}
	statsMu.Lock()
	defer statsMu.Unlock()
	statsData = append(statsData, entries...)
	if n := len(statsData); n > maxStatsEntries {
		// keep the newest maxStatsEntries in one slice op (copy so the evicted
		// head's backing array can be freed instead of leaking behind the slice).
		statsData = append([]statsEntry(nil), statsData[n-maxStatsEntries:]...)
	}
}

// statsTimeline buckets the persistent stats store's last 24h of drops into
// hourly counts (oldest first), same layout as DropsResp.Timeline.
func statsTimeline(now time.Time) []int {
	tl := make([]int, 24)
	statsMu.Lock()
	defer statsMu.Unlock()
	for _, e := range statsData {
		// age in whole seconds first: int() truncates toward zero, so a
		// slightly-future timestamp would otherwise land in the newest bucket.
		if age := now.Unix() - e.Ts; age >= 0 && age < 24*3600 {
			tl[23-int(age/3600)]++
		}
	}
	return tl
}

// backfillFromStats fills a DropsResp from the persistent stats store. It always
// merges the 24h timeline (taking the fuller of live vs stored per bucket, since
// the NFLOG ring is in-memory and empty right after a restart) and keeps Total
// consistent with the chart. The recent list and the per-port / per-country
// breakdowns are only filled when the live feed produced nothing — so a working
// live source is never overwritten, but a live-starved caller (web service holds
// the single NFLOG group, or the kernel log is unreadable in a container) still
// gets a populated dashboard and Logs tab. The store lacks direction/proto, so
// reconstructed drops are attributed to ingress with an empty proto.
func backfillFromStats(resp *DropsResp, now time.Time) {
	backfillFromStatsLimit(resp, now, defaultRecentLogLimit)
}

func backfillFromStatsLimit(resp *DropsResp, now time.Time, recentLimit int) {
	statsMu.Lock()
	defer statsMu.Unlock()
	if len(statsData) == 0 {
		return
	}
	tl := make([]int, 24)
	ports := map[string]int{}
	cc := map[string]int{}
	for _, e := range statsData {
		if age := now.Unix() - e.Ts; age >= 0 && age < 24*3600 {
			tl[23-int(age/3600)]++
			if e.Port != "" {
				ports[e.Port]++
			}
			if e.CC != "" {
				cc[e.CC]++
			}
		}
	}
	for i, v := range tl {
		if v > resp.Timeline[i] {
			resp.Timeline[i] = v
		}
	}
	sum := 0
	for _, v := range resp.Timeline {
		sum += v
	}
	if sum > resp.Total {
		resp.Total = sum
	}
	if len(resp.TopPorts) == 0 {
		resp.TopPorts = ports
	}
	if len(resp.IngressByCC) == 0 && len(resp.EgressByCC) == 0 {
		resp.IngressByCC = cc
	}
	if len(resp.Recent) == 0 {
		// statsData is appended in ingest (≈time) order, so the tail is newest.
		start := len(statsData) - recentLimit
		if start < 0 {
			start = 0
		}
		for i := len(statsData) - 1; i >= start; i-- {
			e := statsData[i]
			resp.Recent = append(resp.Recent, Drop{
				Time:    time.Unix(e.Ts, 0).UTC().Format(time.RFC3339),
				Src:     e.Src,
				Dport:   e.Port,
				Dir:     "ingress",
				CC:      e.CC,
				Reason:  e.Reason,
				Verdict: "drop",
			})
		}
	}
}

// topIPs returns top source IPs by drop count within [from, to] unix timestamps.
func topIPs(from, to int64, limit int) []map[string]interface{} {
	statsMu.Lock()
	defer statsMu.Unlock()
	if limit <= 0 {
		limit = 20
	}
	type cnt struct {
		n    int
		cc   string
		last int64
	}
	m := map[string]*cnt{}
	for _, e := range statsData {
		if e.Ts < from || (to > 0 && e.Ts > to) {
			continue
		}
		if c, ok := m[e.Src]; ok {
			c.n++
			if e.Ts > c.last {
				c.last = e.Ts
			}
		} else {
			m[e.Src] = &cnt{n: 1, cc: e.CC, last: e.Ts}
		}
	}
	type kv struct {
		ip   string
		n    int
		cc   string
		last int64
	}
	var all []kv
	for ip, c := range m {
		all = append(all, kv{ip, c.n, c.cc, c.last})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].n > all[j].n })
	if len(all) > limit {
		all = all[:limit]
	}
	out := make([]map[string]interface{}, len(all))
	for i, a := range all {
		out[i] = map[string]interface{}{
			"ip":   a.ip,
			"hits": a.n,
			"cc":   a.cc,
			"last": a.last,
		}
	}
	return out
}

// ipHistogram returns the top-N source IPs over [from,now] with per-bucket
// drop counts (for the per-IP mini-histograms on the SOC overview). buckets
// counts are oldest-first.
const (
	defaultIPHistogramBuckets = 30
	maxIPHistogramBuckets     = 360
)

// histogramBucketCount maps an API request to one of the supported fixed
// resolutions. The returned value must never carry user input into make.
func histogramBucketCount(requested int) int {
	switch {
	case requested <= 0:
		return defaultIPHistogramBuckets
	case requested <= 10:
		return 10
	case requested <= 20:
		return 20
	case requested <= defaultIPHistogramBuckets:
		return defaultIPHistogramBuckets
	case requested <= 40:
		return 40
	case requested <= 60:
		return 60
	case requested <= 120:
		return 120
	default:
		return maxIPHistogramBuckets
	}
}

func ipHistogram(from int64, buckets, limit int) map[string]interface{} {
	if limit <= 0 {
		limit = 10
	}
	buckets = histogramBucketCount(buckets)
	now := time.Now().Unix()
	if from <= 0 || from >= now {
		from = now - 3600
	}
	span := now - from
	statsMu.Lock()
	type acc struct {
		n    int
		cc   string
		b    []int
		last int64
	}
	m := map[string]*acc{}
	for _, e := range statsData {
		if e.Ts < from || e.Ts > now {
			continue
		}
		a, ok := m[e.Src]
		if !ok {
			a = &acc{cc: e.CC, b: make([]int, buckets)}
			m[e.Src] = a
		}
		a.n++
		if e.Ts > a.last {
			a.last = e.Ts
		}
		bi := int((e.Ts - from) * int64(buckets) / span)
		if bi >= buckets {
			bi = buckets - 1
		}
		a.b[bi]++
	}
	statsMu.Unlock()
	type row struct {
		ip string
		a  *acc
	}
	var all []row
	for ip, a := range m {
		all = append(all, row{ip, a})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].a.n > all[j].a.n })
	if len(all) > limit {
		all = all[:limit]
	}
	out := make([]map[string]interface{}, len(all))
	for i, r := range all {
		out[i] = map[string]interface{}{
			"ip": r.ip, "hits": r.a.n, "cc": r.a.cc, "last": r.a.last, "buckets": r.a.b,
		}
	}
	return map[string]interface{}{"from": from, "to": now, "buckets": buckets, "ips": out}
}

// dumpStats writes the in-memory stats to disk.
func dumpStats() {
	statsMu.Lock()
	defer statsMu.Unlock()
	b, err := json.Marshal(statsData)
	if err != nil {
		return
	}
	os.WriteFile(statsFile, b, 0600)
}

// loadStats reads persisted stats from disk on startup.
func loadStats() {
	b, err := os.ReadFile(statsFile)
	if err != nil {
		return
	}
	var entries []statsEntry
	if json.Unmarshal(b, &entries) == nil {
		statsMu.Lock()
		statsData = entries
		statsMu.Unlock()
		// Resume the high-water-mark from the newest persisted drop, so a restart
		// doesn't re-ingest (and double-count) the overlap window.
		for _, e := range entries {
			if e.Ts > lastIngestTs {
				lastIngestTs = e.Ts
			}
		}
	}
}

// filterNewDrops turns kernel drops into stats entries, keeping only those newer
// than 'after' (unix ts) so re-polling the same window never double-counts.
// Returns the new entries and the new high-water-mark (>= after).
func filterNewDrops(recent []Drop, after, now int64) ([]statsEntry, int64) {
	entries := make([]statsEntry, 0, len(recent))
	hw := after
	for _, dr := range recent {
		ts := now
		if t, err := time.Parse(time.RFC3339, dr.Time); err == nil {
			ts = t.Unix()
		}
		if ts <= after {
			continue // already ingested on an earlier tick
		}
		if ts > hw {
			hw = ts
		}
		entries = append(entries, statsEntry{Ts: ts, Src: dr.Src, CC: dr.CC, Port: dr.Dport, Reason: dr.Reason})
	}
	return entries, hw
}

// ingestDropsLog reads recent kernel drops and feeds the new ones into the stats
// store. Called on a ticker; dedups via lastIngestTs.
// ingestDropsLog records the newly-seen drops and returns how many were added
// (0 = nothing new, so the caller can skip the disk write).
func ingestDropsLog() int {
	d := drops("-1h")
	entries, hw := filterNewDrops(d.Recent, lastIngestTs, time.Now().Unix())
	lastIngestTs = hw
	recordStats(entries)
	return len(entries)
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
			var pr PolicyRule
			switch ruleKind(fields) {
			case "filter":
				if len(fields) < 5 {
					continue
				}
				pr = PolicyRule{Action: fields[0], Dir: fields[1], Proto: fields[2], Port: fields[3], Target: fields[4]}
				for i := 5; i < len(fields)-1; i++ {
					if fields[i] == "on" {
						pr.Iface = fields[i+1]
					}
				}
			case "zone":
				if len(fields) < 6 {
					continue
				}
				pr = PolicyRule{Kind: "zone", Action: fields[0], Src: fields[1], Dst: fields[3], Proto: fields[4], Port: fields[5]}
				if len(fields) >= 8 && fields[6] == "from" {
					pr.Geo = fields[7]
				}
			case "nat":
				if len(fields) < 3 {
					continue
				}
				pr = PolicyRule{Kind: "nat", Text: strings.Join(fields, " ")}
				for i := 1; i < len(fields)-1; i++ {
					if fields[i] == "on" {
						pr.Iface = fields[i+1]
					}
				}
			case "synproxy":
				if len(fields) < 4 {
					continue
				}
				pr = PolicyRule{Kind: "synproxy", Action: fields[0], Dir: fields[1], Proto: fields[2], Port: fields[3]}
				for i := 4; i < len(fields)-1; i++ {
					if fields[i] == "on" {
						pr.Iface = fields[i+1]
					}
				}
			default: // throttle & unknown: not shown in the read-only policy list
				continue
			}
			n++
			pr.Num = n
			pr.Comment = comment
			pr.File = base
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
		case k == "ABUSE_FEEDS":
			feeds = strings.Fields(v)
		}
	}
	// Whitelist is file-managed (whitelist.conf / whitelist-hosts.conf), with the
	// legacy config vars as a fallback — same precedence the engine uses.
	wl = currentWhitelist()
	wlh = currentWhitelistHosts()
	return map[string]interface{}{"groups": groups, "regions": regions,
		"whitelist": wl, "whitelistHosts": wlh, "feeds": feeds,
		"zones": zoneNames(), "abuseSources": abuseSources(), "abuseLoaded": abuseLoadedCount(),
		"lists": []map[string]string{}}
}

// readListFile reads a whitelist-style file: one entry per line, skipping blank
// lines and # comments. Returns nil if the file doesn't exist or has no entries.
func readListFile(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseList(string(data))
}

// extractConfigVar scans config-style content for KEY="value" (or KEY=value)
// and returns the whitespace-split fields. Used as the legacy fallback when the
// dedicated whitelist file has no entries.
func extractConfigVar(data []byte, key string) []string {
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			continue
		}
		if strings.TrimSpace(line[:eq]) == key {
			return strings.Fields(strings.Trim(strings.TrimSpace(line[eq+1:]), `"`))
		}
	}
	return nil
}

// currentWhitelist / currentWhitelistHosts return the effective entries the way
// the engine sees them: the dedicated file when it has any entry, else the
// legacy config variable. Keeps the UI and the engine in agreement.
func currentWhitelist() []string {
	if wl := readListFile(whitelistFile); len(wl) > 0 {
		return wl
	}
	data, _ := os.ReadFile(configFile)
	return extractConfigVar(data, "WHITELIST")
}

func currentWhitelistHosts() []string {
	if wlh := readListFile(whitelistHostsFile); len(wlh) > 0 {
		return wlh
	}
	data, _ := os.ReadFile(configFile)
	return extractConfigVar(data, "WHITELIST_HOSTS")
}

// ruleStats counts rules by action and target type across all rule files,
// and reports how many addresses are in the whitelist. This gives the operator
// a quick breakdown of "how many rules hit the whitelist path vs deny vs allow"
// without parsing nft output.
func ruleStats() map[string]interface{} {
	stats := map[string]interface{}{
		"allow": 0, "deny": 0, "throttle": 0, "synproxy": 0,
		"nat": 0, "zone": 0, "total": 0,
		"denyAbuse": 0, "allowAny": 0,
	}
	for _, rf := range ruleFileList() {
		items, _ := parseDraftRules(draftTextFor(rf))
		for _, it := range items {
			if it.Kind == "section" || it.Disabled {
				continue
			}
			stats["total"] = stats["total"].(int) + 1
			switch it.Kind {
			case "nat":
				stats["nat"] = stats["nat"].(int) + 1
			case "zone":
				stats["zone"] = stats["zone"].(int) + 1
			case "synproxy":
				stats["synproxy"] = stats["synproxy"].(int) + 1
			case "throttle":
				stats["throttle"] = stats["throttle"].(int) + 1
			default:
				switch it.Action {
				case "allow":
					stats["allow"] = stats["allow"].(int) + 1
					if it.Target == "any" {
						stats["allowAny"] = stats["allowAny"].(int) + 1
					}
				case "deny":
					stats["deny"] = stats["deny"].(int) + 1
					if it.Target == "abuse" {
						stats["denyAbuse"] = stats["denyAbuse"].(int) + 1
					}
				}
			}
		}
	}
	// whitelist address counts from config
	obj := objects()
	wl, _ := obj["whitelist"].([]string)
	wlh, _ := obj["whitelistHosts"].([]string)
	stats["whitelistIPs"] = len(wl)
	stats["whitelistHosts"] = len(wlh)
	stats["whitelistTotal"] = len(wl) + len(wlh)
	// live whitelist hit counters from baseline
	bc := baselineCounters()
	var wlHits int64
	for _, c := range bc {
		if n, ok := c["whitelist"]; ok {
			wlHits += n
		}
	}
	stats["whitelistHits"] = wlHits
	return stats
}

// hostInterfaces lists the machine's network interface names for the rule
// drawers' interface picker. It backs a datalist, so free text is still allowed
// for tunnel/VPN interfaces that only appear later. Loopback is listed last.
func hostInterfaces() []string {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var names, lo []string
	for _, i := range ifs {
		if i.Name == "lo" {
			lo = append(lo, i.Name)
			continue
		}
		names = append(names, i.Name)
	}
	sort.Strings(names)
	return append(names, lo...)
}

// zoneNames collects the lowercased ZONE_<NAME> keys from the config and every
// groups.d/*.conf drop-in, for the inter-zone rule drawer's autocomplete (zones
// have no Objects tab of their own).
func zoneNames() []string {
	files := []string{configFile}
	if ents, err := os.ReadDir(groupsDir); err == nil {
		for _, e := range ents {
			if strings.HasSuffix(e.Name(), ".conf") {
				files = append(files, filepath.Join(groupsDir, e.Name()))
			}
		}
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range files {
		data, _ := os.ReadFile(f)
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "ZONE_") {
				continue
			}
			if eq := strings.Index(line, "="); eq > 5 {
				name := strings.ToLower(strings.TrimSpace(line[5:eq]))
				if name != "" && !seen[name] {
					seen[name] = true
					out = append(out, name)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func countLines(p string) int {
	f, err := os.Open(p)
	if err != nil {
		return 0
	}
	defer f.Close()

	n := 0
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		n++
	}
	return n
}

// abuseSources reports what populates the "abuse" blocklist: the AbuseIPDB
// retained state plus each cached ABUSE_FEEDS file, with entry count and age.
func abuseSources() []map[string]interface{} {
	var out []map[string]interface{}
	add := func(name, path string, fi os.FileInfo) {
		age := time.Since(fi.ModTime())
		out = append(out, map[string]interface{}{"name": name, "count": countLines(path),
			"ageHours": int(age.Hours()), "fresh": age < 26*time.Hour})
	}
	stateFile := env("ABUSEIPDB_STATE_FILE", filepath.Join(stateDir, "abuseipdb.tsv"))
	if fi, err := os.Stat(stateFile); err == nil {
		add("AbuseIPDB", stateFile, fi)
	}
	labels := feedLabels()
	if ents, err := os.ReadDir(feedsDir); err == nil {
		for _, e := range ents {
			if fi, err := e.Info(); err == nil {
				name := labels[e.Name()]
				if name == "" {
					name = shortFeed(e.Name())
				}
				add(name, filepath.Join(feedsDir, e.Name()), fi)
			}
		}
	}
	return out
}

// abuseLoadedCount is the number of unique entries actually in the abuse sets.
// The engine writes the deduplicated, scrubbed, CIDR-aggregated set to STATE_DIR
// after each run, so this is the real total loaded into the firewall. Per-source
// counts overlap (one IP can be on many feeds), so their sum is always larger.
func abuseLoadedCount() int {
	return countLines(filepath.Join(stateDir, "abuse4.set")) +
		countLines(filepath.Join(stateDir, "abuse6.set"))
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

// rdapCIDR renders one RDAP cidr0_cidrs entry as "prefix/length". The cidr0
// extension carries the base in "v4prefix" for IPv4 blocks and "v6prefix" for
// IPv6; using only one printed "<nil>/29" for the other family. Empty if absent.
func rdapCIDR(cm map[string]interface{}) string {
	prefix := cm["v4prefix"]
	if prefix == nil {
		prefix = cm["v6prefix"]
	}
	if prefix == nil {
		return ""
	}
	return fmt.Sprintf("%v/%v", prefix, cm["length"])
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
					if s := rdapCIDR(cm); s != "" {
						w["cidr"] = s
					}
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

func writeJSONCached(w http.ResponseWriter, r *http.Request, v interface{}) {
	b, err := json.Marshal(v)
	if err != nil {
		writeJSON(w, v)
		return
	}
	h := sha256.Sum256(b)
	etag := `"` + hex.EncodeToString(h[:]) + `"`
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "no-cache")
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(b)
}

// ---- auth: root-minted HMAC token -> HttpOnly session cookie ----------------

var (
	secretFile = env("UI_SECRET_FILE", "/var/lib/nftgeo/ui-secret")
	authSecret []byte
	authOn     bool
	sessionTTL = parseDur(env("UI_SESSION_TTL", "15m"), 15*time.Minute)

	sessMu         sync.Mutex
	sessions       = map[string]*uiSession{}
	usedNonce      = map[string]time.Time{} // nonce -> time added; pruned in sweepSessions
	pendingSession *pendingReq
)

type uiSession struct {
	mode string
	last time.Time
}

type pendingReq struct {
	id      string
	mode    string
	nonce   string
	expires time.Time
	status  string
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

// sessionCookie marks cookies Secure whenever the browser connection is HTTPS.
// A local TLS-terminating reverse proxy must pass X-Forwarded-Proto: https.
func sessionCookie(r *http.Request, sid string) *http.Cookie {
	return &http.Cookie{
		Name:     "nftgeo_sess",
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https"),
		SameSite: http.SameSiteStrictMode,
	}
}

func handleSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		Auth string `json:"auth"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	mode, nonce, ok := verifyToken(body.Auth)
	if !ok {
		http.Error(w, `{"error":"invalid or expired token"}`, http.StatusUnauthorized)
		return
	}
	sessMu.Lock()
	if mode == "rw" { // full-access bootstrap tokens are single-use
		if _, used := usedNonce[nonce]; used {
			sessMu.Unlock()
			http.Error(w, `{"error":"token already used"}`, http.StatusUnauthorized)
			return
		}
		usedNonce[nonce] = time.Now()

		// A fresh token presented by the browser that already holds the active rw
		// session is the same operator re-authenticating — retire that session so
		// the takeover is instant instead of routing through the 30s approval
		// prompt (which nothing could answer once this tab reloads).
		if c, err := r.Cookie("nftgeo_sess"); err == nil {
			if s := sessions[c.Value]; s != nil && s.mode == "rw" {
				delete(sessions, c.Value)
			}
		}

		// Check for an existing rw session to trigger approval
		hasActiveRW := false
		for _, s := range sessions {
			if s.mode == "rw" && time.Since(s.last) <= sessionTTL {
				hasActiveRW = true
				break
			}
		}

		if hasActiveRW {
			reqID := randHex(24)
			pendingSession = &pendingReq{
				id:      reqID,
				mode:    mode,
				nonce:   nonce,
				expires: time.Now().Add(30 * time.Second),
				status:  "pending",
			}
			sessMu.Unlock()
			writeJSON(w, map[string]interface{}{"status": "pending", "poll_id": reqID})
			return
		}
	}

	sid := randHex(24)
	sessions[sid] = &uiSession{mode: mode, last: time.Now()}
	sessMu.Unlock()
	http.SetCookie(w, sessionCookie(r, sid))
	writeJSON(w, map[string]interface{}{"mode": mode})
}

func handleSessionPoll(w http.ResponseWriter, r *http.Request) {
	if !authOn {
		writeJSON(w, map[string]interface{}{"error": "auth disabled"})
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
		return
	}
	var body struct {
		PollID string `json:"poll_id"`
	}
	json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&body)

	sessMu.Lock()
	defer sessMu.Unlock()

	if pendingSession == nil || pendingSession.id != body.PollID {
		http.Error(w, `{"error":"invalid poll_id"}`, http.StatusNotFound)
		return
	}

	if time.Now().After(pendingSession.expires) {
		// Timeout -> accept by default as requested: "jesli ktos wygenruje nowy token i toworzy nim przegladarke chce miec 30 s ostrzezenia... mzoliwosc jej przerwania"
		// If they don't interrupt it, it proceeds.
		if pendingSession.status == "pending" {
			pendingSession.status = "accepted"
		}
	}

	if pendingSession.status == "rejected" {
		pendingSession = nil
		http.Error(w, `{"error":"session rejected by current user"}`, http.StatusForbidden)
		return
	}

	if pendingSession.status == "accepted" {
		// Drop all old rw sessions
		for id, s := range sessions {
			if s.mode == "rw" {
				delete(sessions, id)
			}
		}

		sid := randHex(24)
		sessions[sid] = &uiSession{mode: pendingSession.mode, last: time.Now()}
		mode := pendingSession.mode
		pendingSession = nil
		http.SetCookie(w, sessionCookie(r, sid))
		writeJSON(w, map[string]interface{}{"status": "ok", "mode": mode})
		return
	}

	writeJSON(w, map[string]interface{}{"status": "pending"})
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
		// Prune nonces older than 24h — they can't be replayed after the
		// token expires (rw tokens expire after 10 min, ro after 90 days,
		// but ro tokens aren't tracked in usedNonce). 24h is a safe margin.
		for n, t := range usedNonce {
			if time.Since(t) > 24*time.Hour {
				delete(usedNonce, n)
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
	raw := fs.Bool("raw", false, "print only the raw token (no URL or other text)")
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

	if *raw {
		fmt.Print(tok)
		return
	}

	url := fmt.Sprintf("http://%s/#auth=%s", *addr, tok)

	// Fancy output
	fmt.Printf("\033[1;32m=== NFTGEO-UI SESSION TOKEN ===\033[0m\n\n")
	fmt.Printf("Valid until: \033[1m%s\033[0m\n", exp.Format("2006-01-02 15:04 MST"))
	if mode == "ro" {
		fmt.Printf("Mode:        \033[1;36mRead-Only\033[0m (panel only, no firewall changes)\n")
	} else {
		fmt.Printf("Mode:        \033[1;31mFull Read-Write\033[0m (one-time link, expires after %s of inactivity)\n", sessionTTL)
	}
	fmt.Printf("\nClick the link below to open the dashboard:\n")
	// Clickable URL using ANSI OSC 8
	fmt.Printf("\033]8;;%s\033\\\033[4;36m%s\033[0m\033]8;;\033\\\n\n", url, url)
	fmt.Printf("Or copy the token directly:\n\033[1;33m%s\033[0m\n\n", tok)
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
	nftgeoBin = env("NFTGEO_BIN", "/usr/sbin/nftgeo")
	stateDir  = env("STATE_DIR", "/var/lib/nftgeo")
	groupsDir = env("GROUPS_DIR", "/etc/nftgeo/groups.d")
	sentinel  = env("SENTINEL", filepath.Join(stateDir, ".pending-confirm"))

	// Per-file staging: every rule file (rules.conf + each rules.d/*.conf) and the
	// objects drop-in are drafted under these dirs, mirroring the live layout.
	draftDir  = filepath.Join(stateDir, "ui-drafts")
	backupDir = filepath.Join(stateDir, "ui-backups")

	// objects staging (M6B.2): GROUP_*/REGION_*/SERVICE_* live in a UI-owned
	// groups.d drop-in, sourced by the engine after config.
	objLiveFile   = filepath.Join(groupsDir, "ui-objects.conf")
	objDraftFile  = filepath.Join(draftDir, "objects")
	objBackupFile = filepath.Join(backupDir, "objects")

	// Whitelist staging: whitelist.conf + whitelist-hosts.conf get the same
	// draft → commit → deadman pipeline as rules and objects.
	wlDraftFile       = filepath.Join(draftDir, "whitelist")
	wlBackupFile      = filepath.Join(backupDir, "whitelist")
	wlHostsDraftFile  = filepath.Join(draftDir, "whitelist-hosts")
	wlHostsBackupFile = filepath.Join(backupDir, "whitelist-hosts")
)

// A stage is one file the UI drafts and commits: the operator edits `draft`,
// Commit backs up `live`, promotes `draft` -> `live`, and the pipeline can
// restore `live` from `backup` on rollback / deadman / interrupted deploy.
type stage struct{ name, draft, live, backup string }

// ruleFile is one editable rules file: rules.conf or a rules.d/*.conf drop-in.
// The engine reads rules.conf first, then rules.d/*.conf in sorted order.
type ruleFile struct{ rel, live, draft, backup string }

func ruleFileList() []ruleFile {
	mk := func(live, rel string) ruleFile {
		return ruleFile{rel: rel, live: live,
			draft: filepath.Join(draftDir, rel), backup: filepath.Join(backupDir, rel)}
	}
	out := []ruleFile{mk(rulesFile, "rules.conf")}
	if ents, err := os.ReadDir(rulesDir); err == nil {
		var names []string
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, mk(filepath.Join(rulesDir, n), "rules.d/"+n))
		}
	}
	// Ingress hook files (early stateless drop): ingress.conf, then ingress.d/*.
	// Shown as their own "Ingress" chain group; they use the same draft/commit.
	out = append(out, mk(ingressFile, "ingress.conf"))
	if ents, err := os.ReadDir(ingressDir); err == nil {
		var names []string
		for _, e := range ents {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".conf") {
				names = append(names, e.Name())
			}
		}
		sort.Strings(names)
		for _, n := range names {
			out = append(out, mk(filepath.Join(ingressDir, n), "ingress.d/"+n))
		}
	}
	return out
}

// findRuleFile resolves an editable rule file by its relative name (default
// rules.conf). Returns nil for an unknown name (so callers reject bad input
// instead of writing outside the managed set).
func findRuleFile(rel string) *ruleFile {
	if rel == "" {
		rel = "rules.conf"
	}
	for _, rf := range ruleFileList() {
		if rf.rel == rel {
			r := rf
			return &r
		}
	}
	return nil
}

func draftTextFor(rf ruleFile) string {
	if b, err := os.ReadFile(rf.draft); err == nil {
		return string(b)
	}
	return readFileStr(rf.live)
}

func writeDraftFor(rf ruleFile, items []*draftRule, tail []string) error {
	os.MkdirAll(filepath.Dir(rf.draft), 0755)
	return os.WriteFile(rf.draft, []byte(serializeDraftRules(items, tail)), 0644)
}

func stages() []stage {
	var s []stage
	for _, rf := range ruleFileList() {
		s = append(s, stage{name: "rule:" + rf.rel, draft: rf.draft, live: rf.live, backup: rf.backup})
	}
	return append(s, stage{name: "objects", draft: objDraftFile, live: objLiveFile, backup: objBackupFile},
		stage{name: "whitelist", draft: wlDraftFile, live: whitelistFile, backup: wlBackupFile},
		stage{name: "whitelist-hosts", draft: wlHostsDraftFile, live: whitelistHostsFile, backup: wlHostsBackupFile})
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
	if err := os.MkdirAll(filepath.Dir(s.backup), 0755); err != nil {
		return err
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
// state (draft rules across every file + draft objects) without touching any
// live file. Returns a cleanup to remove any temp dirs.
func previewEnv() ([]string, func()) {
	var envv []string
	var tmps []string
	cleanup := func() {
		for _, t := range tmps {
			os.RemoveAll(t)
		}
	}
	files := ruleFileList()

	// rules.conf: point RULES_FILE at its draft if one exists.
	for _, rf := range files {
		if rf.rel == "rules.conf" {
			if _, e := os.Stat(rf.draft); e == nil {
				envv = append(envv, "RULES_FILE="+rf.draft)
			}
		}
	}
	// rules.d: if any drop-in has a draft, render from a temp dir holding the
	// draft-or-live version of every drop-in.
	anyDD := false
	for _, rf := range files {
		if strings.HasPrefix(rf.rel, "rules.d/") {
			if _, e := os.Stat(rf.draft); e == nil {
				anyDD = true
			}
		}
	}
	if anyDD {
		if tmp, err := os.MkdirTemp("", "nftgeo-rd-*"); err == nil {
			for _, rf := range files {
				if !strings.HasPrefix(rf.rel, "rules.d/") {
					continue
				}
				src := rf.live
				if _, e := os.Stat(rf.draft); e == nil {
					src = rf.draft
				}
				if b, e := os.ReadFile(src); e == nil {
					os.WriteFile(filepath.Join(tmp, strings.TrimPrefix(rf.rel, "rules.d/")), b, 0644)
				}
			}
			envv = append(envv, "RULES_DIR="+tmp)
			tmps = append(tmps, tmp)
		}
	}
	// ingress.conf: point INGRESS_FILE at its draft if one exists.
	for _, rf := range files {
		if rf.rel == "ingress.conf" {
			if _, e := os.Stat(rf.draft); e == nil {
				envv = append(envv, "INGRESS_FILE="+rf.draft)
			}
		}
	}
	// ingress.d: mirror rules.d — render from a temp dir of draft-or-live drop-ins.
	anyID := false
	for _, rf := range files {
		if strings.HasPrefix(rf.rel, "ingress.d/") {
			if _, e := os.Stat(rf.draft); e == nil {
				anyID = true
			}
		}
	}
	if anyID {
		if tmp, err := os.MkdirTemp("", "nftgeo-id-*"); err == nil {
			for _, rf := range files {
				if !strings.HasPrefix(rf.rel, "ingress.d/") {
					continue
				}
				src := rf.live
				if _, e := os.Stat(rf.draft); e == nil {
					src = rf.draft
				}
				if b, e := os.ReadFile(src); e == nil {
					os.WriteFile(filepath.Join(tmp, strings.TrimPrefix(rf.rel, "ingress.d/")), b, 0644)
				}
			}
			envv = append(envv, "INGRESS_DIR="+tmp)
			tmps = append(tmps, tmp)
		}
	}
	// objects drop-in.
	if _, e := os.Stat(objDraftFile); e == nil {
		if tmp, err := os.MkdirTemp("", "nftgeo-gd-*"); err == nil {
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
			tmps = append(tmps, tmp)
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
	rf := findRuleFile(r.URL.Query().Get("file"))
	if rf == nil {
		http.Error(w, `{"error":"unknown rule file"}`, http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		live := readFileStr(rf.live)
		text, exists := live, false
		if b, err := os.ReadFile(rf.draft); err == nil {
			text, exists = string(b), true
		}
		diff, changed := "", 0
		if exists {
			diff, changed = diffText(live, text)
		}
		writeJSON(w, map[string]interface{}{"file": rf.rel, "exists": exists, "live": live, "draft": text, "diff": diff, "changed": changed})
	case http.MethodPut:
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			http.Error(w, `{"error":"read failed"}`, http.StatusBadRequest)
			return
		}
		os.MkdirAll(filepath.Dir(rf.draft), 0755)
		if err := os.WriteFile(rf.draft, body, 0644); err != nil {
			http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
			return
		}
		_, changed := diffText(readFileStr(rf.live), string(body))
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

var objLineRe = regexp.MustCompile(`^(GROUP|REGION|SERVICE|HOST|ZONE|LIST|FEED)_([A-Za-z0-9_]+)=(.*)$`)
var objNameRe = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
var zoneMemberRe = regexp.MustCompile(`^[A-Za-z0-9._@:-]+$`) // interface names incl. VLAN subif (eth0.100)
var objMemberRe = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)

// feedURLRe validates a custom abuse-feed URL. The value is written into a
// double-quoted, shell-sourced assignment (ABUSE_FEEDS_UI="..."), so it must
// contain no whitespace and none of the shell-dangerous chars " ' ` $ \ < > .
var feedURLRe = regexp.MustCompile("^https?://[^\\s\"'`$\\\\<>]+$")

func parseObjects(text string) (groups, regions, services, hosts, zones, lists, feeds []objEntry) {
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := objLineRe.FindStringSubmatch(line)
		if m == nil {
			continue // includes the derived ABUSE_FEEDS_UI= line, rebuilt from FEED_*
		}
		val := strings.Trim(strings.TrimSpace(m[3]), `"`)
		e := objEntry{Name: m[2], Members: strings.Fields(val)}
		switch m[1] {
		case "GROUP":
			groups = append(groups, e)
		case "REGION":
			regions = append(regions, e)
		case "HOST":
			hosts = append(hosts, e)
		case "ZONE":
			zones = append(zones, e)
		case "LIST":
			lists = append(lists, e)
		case "FEED":
			feeds = append(feeds, e)
		default:
			services = append(services, e)
		}
	}
	return
}

func serializeObjects(groups, regions, services, hosts, zones, lists, feeds []objEntry) string {
	var b strings.Builder
	b.WriteString("# Managed by nftgeo-ui (Objects tab). Do not hand-edit; the panel overwrites this file.\n")
	for _, g := range groups {
		fmt.Fprintf(&b, "GROUP_%s=\"%s\"\n", strings.ToUpper(g.Name), strings.Join(g.Members, " "))
	}
	for _, rg := range regions {
		fmt.Fprintf(&b, "REGION_%s=\"%s\"\n", strings.ToUpper(rg.Name), strings.Join(rg.Members, " "))
	}
	for _, hs := range hosts {
		fmt.Fprintf(&b, "HOST_%s=\"%s\"\n", strings.ToUpper(hs.Name), strings.Join(hs.Members, " "))
	}
	for _, sv := range services {
		fmt.Fprintf(&b, "SERVICE_%s=\"%s\"\n", strings.ToUpper(sv.Name), strings.Join(sv.Members, " "))
	}
	for _, z := range zones {
		fmt.Fprintf(&b, "ZONE_%s=\"%s\"\n", strings.ToUpper(z.Name), strings.Join(z.Members, " "))
	}
	for _, l := range lists {
		fmt.Fprintf(&b, "LIST_%s=\"%s\"\n", strings.ToUpper(l.Name), strings.Join(l.Members, " "))
	}
	// Named abuse feeds (label -> URL[s]) plus a derived ABUSE_FEEDS_UI line that
	// the engine reads (it does not enumerate FEED_* itself).
	var allURLs []string
	for _, fd := range feeds {
		fmt.Fprintf(&b, "FEED_%s=\"%s\"\n", strings.ToUpper(fd.Name), strings.Join(fd.Members, " "))
		allURLs = append(allURLs, fd.Members...)
	}
	if len(allURLs) > 0 {
		fmt.Fprintf(&b, "ABUSE_FEEDS_UI=\"%s\"\n", strings.Join(allURLs, " "))
	}
	return b.String()
}

// checkZones validates zone names + their interface members (which allow the
// VLAN-subinterface dot and other iface characters the address checks reject).
func checkZones(zones []objEntry) error {
	seen := map[string]bool{}
	for _, e := range zones {
		if !objNameRe.MatchString(e.Name) {
			return fmt.Errorf("invalid zone name %q (letters, digits, underscore)", e.Name)
		}
		key := strings.ToUpper(e.Name)
		if seen[key] {
			return fmt.Errorf("duplicate zone %q", e.Name)
		}
		seen[key] = true
		for _, m := range e.Members {
			if !zoneMemberRe.MatchString(m) {
				return fmt.Errorf("invalid interface %q in zone %s", m, e.Name)
			}
		}
	}
	return nil
}

// checkNames validates names/members and rejects duplicates within one namespace
// (the values are sourced by the shell engine, so metacharacters must not pass).
func checkNames(lists ...[]objEntry) error {
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

// sanitizeObjects validates two namespaces separately: address/target names
// (groups + regions + hosts, which all resolve as a rule target) and services.
func sanitizeObjects(groups, regions, services, hosts, zones, lists, feeds []objEntry) error {
	if err := checkNames(groups, regions, hosts); err != nil {
		return err
	}
	if err := checkNames(services); err != nil {
		return err
	}
	if err := checkNames(lists); err != nil {
		return err
	}

	// Validate IP/CIDR for hosts and lists
	for _, l := range [][]objEntry{hosts, lists} {
		for _, e := range l {
			for _, m := range e.Members {
				_, _, errCIDR := net.ParseCIDR(m)
				if net.ParseIP(m) == nil && errCIDR != nil {
					return fmt.Errorf("invalid IP/CIDR %q in %s", m, e.Name)
				}
			}
		}
	}
	seen := map[string]bool{}
	for _, fd := range feeds {
		if !objNameRe.MatchString(fd.Name) {
			return fmt.Errorf("invalid feed label %q (letters, digits, underscore)", fd.Name)
		}
		if seen[strings.ToUpper(fd.Name)] {
			return fmt.Errorf("duplicate feed label %q", fd.Name)
		}
		seen[strings.ToUpper(fd.Name)] = true
		if len(fd.Members) == 0 {
			return fmt.Errorf("feed %q has no URL", fd.Name)
		}
		for _, u := range fd.Members {
			if !feedURLRe.MatchString(u) {
				return fmt.Errorf("invalid feed URL %q (http(s):// only, no spaces or shell metacharacters)", u)
			}
		}
	}
	return checkZones(zones)
}

// writeObjectsDraft validates the full object set and stages it into the
// objects draft file, returning the number of changed lines vs live. It is the
// single objects write path shared by the web PUT handler and the console TUI.
// Extracted mutations follow one convention: errMsg is "" on success, else a
// human message plus the HTTP status the web wrapper should return (the TUI
// just shows the message).
func writeObjectsDraft(groups, regions, services, hosts, zones, lists, feeds []objEntry) (changed int, errMsg string, code int) {
	if err := sanitizeObjects(groups, regions, services, hosts, zones, lists, feeds); err != nil {
		return 0, err.Error(), http.StatusBadRequest
	}
	out := serializeObjects(groups, regions, services, hosts, zones, lists, feeds)
	os.MkdirAll(filepath.Dir(objDraftFile), 0755)
	if err := os.WriteFile(objDraftFile, []byte(out), 0644); err != nil {
		return 0, "cannot write objects draft", http.StatusInternalServerError
	}
	_, changed = diffText(readFileStr(objLiveFile), out)
	return changed, "", 0
}

func handleObjectsDraft(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		text := readFileStr(objLiveFile)
		_, exists := os.Stat(objDraftFile)
		if exists == nil {
			text = readFileStr(objDraftFile)
		}
		g, rg, sv, hs, zn, ls, fd := parseObjects(text)
		if g == nil {
			g = []objEntry{}
		}
		if rg == nil {
			rg = []objEntry{}
		}
		if sv == nil {
			sv = []objEntry{}
		}
		if hs == nil {
			hs = []objEntry{}
		}
		if zn == nil {
			zn = []objEntry{}
		}
		if ls == nil {
			ls = []objEntry{}
		}
		if fd == nil {
			fd = []objEntry{}
		}
		writeJSONCached(w, r, map[string]interface{}{"file": objLiveFile, "hasDraft": exists == nil, "groups": g, "regions": rg, "services": sv, "hosts": hs, "zones": zn, "lists": ls, "feeds": fd})
	case http.MethodPut:
		var req struct {
			Groups   []objEntry `json:"groups"`
			Regions  []objEntry `json:"regions"`
			Services []objEntry `json:"services"`
			Hosts    []objEntry `json:"hosts"`
			Zones    []objEntry `json:"zones"`
			Lists    []objEntry `json:"lists"`
			Feeds    []objEntry `json:"feeds"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		changed, errMsg, code := writeObjectsDraft(req.Groups, req.Regions, req.Services, req.Hosts, req.Zones, req.Lists, req.Feeds)
		if errMsg != "" {
			http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
			return
		}
		writeJSON(w, map[string]interface{}{"saved": true, "changed": changed})
	default:
		http.Error(w, `{"error":"method"}`, http.StatusMethodNotAllowed)
	}
}

// ---- whitelist draft (issue #37) ----
//
// The whitelist lives in dedicated files (whitelist.conf / whitelist-hosts.conf)
// and is edited through the same draft → commit → deadman pipeline as rules and
// objects, so a whitelist change can no longer lock you out with no rollback.

// parseList splits list-file content into entries, skipping blanks and #comments.
func parseList(s string) []string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

// saveWhitelistDraft validates and stages the whitelist + whitelist-hosts
// drafts. Single write path shared by the web POST handler and the console
// TUI; same errMsg/code convention as writeObjectsDraft.
func saveWhitelistDraft(entries, hosts []string) (errMsg string, code int) {
	for _, e := range entries {
		if e = strings.TrimSpace(e); e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		if !validWhitelistEntry(e) {
			return "invalid whitelist entry: " + e, http.StatusBadRequest
		}
	}
	for _, e := range hosts {
		if e = strings.TrimSpace(e); e == "" || strings.HasPrefix(e, "#") {
			continue
		}
		if !validHostname(e) {
			return "invalid whitelist host: " + e, http.StatusBadRequest
		}
	}
	os.MkdirAll(filepath.Dir(wlDraftFile), 0755)
	if err := os.WriteFile(wlDraftFile, []byte(serializeListFile(entries)), 0644); err != nil {
		return "cannot write whitelist draft", http.StatusInternalServerError
	}
	if err := os.WriteFile(wlHostsDraftFile, []byte(serializeListFile(hosts)), 0644); err != nil {
		return "cannot write whitelist-hosts draft", http.StatusInternalServerError
	}
	return "", 0
}

// handleWhitelistDraft GETs the current whitelist (draft if present, else the
// effective live entries) and POSTs a new draft. It never writes live files —
// deploying is the operator's explicit Commit, which runs the deadman.
func handleWhitelistDraft(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		wl, wlHasDraft := currentWhitelist(), false
		if b, err := os.ReadFile(wlDraftFile); err == nil {
			wl, wlHasDraft = parseList(string(b)), true
		}
		wlh, wlhHasDraft := currentWhitelistHosts(), false
		if b, err := os.ReadFile(wlHostsDraftFile); err == nil {
			wlh, wlhHasDraft = parseList(string(b)), true
		}
		writeJSONCached(w, r, map[string]interface{}{
			"whitelist": wl, "whitelistHosts": wlh,
			"hasDraft": wlHasDraft || wlhHasDraft,
		})
	case http.MethodPost:
		var req struct {
			Whitelist      []string `json:"whitelist"`
			WhitelistHosts []string `json:"whitelistHosts"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
			http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
			return
		}
		if errMsg, code := saveWhitelistDraft(req.Whitelist, req.WhitelistHosts); errMsg != "" {
			http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
			return
		}
		writeJSON(w, map[string]interface{}{"saved": true})
	default:
		http.Error(w, `{"error":"method"}`, http.StatusMethodNotAllowed)
	}
}

// validWhitelistEntry accepts an IP address or a CIDR range.
func validWhitelistEntry(s string) bool {
	if strings.Contains(s, "/") {
		_, _, err := net.ParseCIDR(s)
		return err == nil
	}
	return net.ParseIP(s) != nil
}

// validHostname does a basic DNS-name char-set check.
func validHostname(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' ||
			c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// serializeListFile renders entries one-per-line under a managed-by header,
// dropping blanks so a round-trip doesn't accumulate empty lines.
func serializeListFile(entries []string) string {
	var b strings.Builder
	b.WriteString("# Managed by nftgeo-ui (Objects → Reference → Whitelist). One entry per line.\n")
	for _, e := range entries {
		if e = strings.TrimSpace(e); e == "" {
			continue
		}
		b.WriteString(e)
		b.WriteString("\n")
	}
	return b.String()
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
	File     string   `json:"file"`
	Kind     string   `json:"kind"`
	Title    string   `json:"title,omitempty"`
	Disabled bool     `json:"disabled"`
	Action   string   `json:"action"`
	Dir      string   `json:"dir"`
	Proto    string   `json:"proto"`
	Port     string   `json:"port"`
	Target   string   `json:"target"`
	Iface    string   `json:"iface"`
	Log      bool     `json:"log"`               // per-rule connection logging
	Rate     string   `json:"rate,omitempty"`    // throttle only
	Ban      string   `json:"ban,omitempty"`     // throttle only
	Src      string   `json:"src,omitempty"`     // zone: source zone
	Dst      string   `json:"dst,omitempty"`     // zone: destination zone
	Geo      string   `json:"geo,omitempty"`     // zone/dnat: optional "from <geo>"
	Text     string   `json:"text,omitempty"`    // nat: verbatim rule text
	NatType  string   `json:"natType,omitempty"` // nat: masquerade | snat | dnat
	Lan      string   `json:"lan,omitempty"`     // nat masquerade/snat: optional inbound iface
	Name     string   `json:"name"`
	Body     string   `json:"body"`
	Trivia   []string `json:"-"`
	Hits     int64    `json:"hits"`
	Matched  bool     `json:"matched"`
}

var sectionRe = regexp.MustCompile(`^#{2,}\s*(.*?)\s*#*$`)

// ruleFields splits a candidate rule line into fields + trailing comment, and
// reports whether it is a valid allow/deny rule.
func ruleFields(s string) (fields []string, body, comment, kind string, ok bool) {
	body = s
	if i := strings.Index(body, "#"); i >= 0 {
		comment = strings.TrimSpace(body[i+1:])
		body = body[:i]
	}
	body = strings.TrimSpace(body)
	f := strings.Fields(body)
	switch ruleKind(f) {
	case "filter", "throttle":
		if len(f) >= 5 {
			return f, body, comment, ruleKind(f), true
		}
	case "zone": // allow|deny <src> -> <dst> <proto> <port> [from <geo>]
		if len(f) >= 6 {
			return f, body, comment, "zone", true
		}
	case "nat": // masquerade on <if> | snat out on <if> to <ip> | dnat <proto> <port> to <ip>[:port] [on <if>]
		if len(f) >= 3 {
			return f, body, comment, "nat", true
		}
	case "synproxy": // synproxy <in|fwd-in> tcp <port> [on <iface>]
		if len(f) >= 4 {
			return f, body, comment, "synproxy", true
		}
	case "ingress": // accept|drop <target> [proto] [port] [log]
		if len(f) >= 2 {
			return f, body, comment, "ingress", true
		}
	}
	return nil, "", "", "", false
}

func mkDraftRule(id int, disabled bool, f []string, body, comment, kind string, trivia []string) *draftRule {
	r := &draftRule{ID: id, Kind: kind, Disabled: disabled, Body: body, Name: comment, Trivia: trivia}
	switch kind {
	case "throttle":
		// throttle <dir> <proto> <port> <rate> [ban <dur>] [on <iface>]
		r.Action, r.Dir, r.Proto, r.Port, r.Rate = f[0], f[1], f[2], f[3], f[4]
		for i := 5; i < len(f)-1; i++ {
			switch f[i] {
			case "on":
				r.Iface = f[i+1]
			case "ban":
				r.Ban = f[i+1]
			}
		}
	case "zone":
		// allow|deny <src> -> <dst> <proto> <port> [from <geo>]
		r.Action, r.Src, r.Dst, r.Proto, r.Port = f[0], f[1], f[3], f[4], f[5]
		if len(f) >= 8 && f[6] == "from" {
			r.Geo = f[7]
		}
	case "synproxy":
		// synproxy <dir> tcp <port> [on <iface>]
		r.Action, r.Dir, r.Proto, r.Port = f[0], f[1], f[2], f[3]
		for i := 4; i < len(f)-1; i++ {
			if f[i] == "on" {
				r.Iface = f[i+1]
			}
		}
	case "nat":
		// masquerade/snat/dnat: keep the verbatim text and also pull the fields so
		// the editor drawer can prefill (natType, iface, geo, target, proto/port).
		r.Text = body
		r.NatType = f[0]
		for i := 1; i < len(f); i++ {
			switch f[i] {
			case "on":
				if i+1 < len(f) {
					r.Iface = f[i+1]
				}
			case "in":
				if i+1 < len(f) {
					r.Lan = f[i+1]
				}
			case "from":
				if i+1 < len(f) {
					r.Geo = f[i+1]
				}
			case "to":
				if i+1 < len(f) {
					r.Target = f[i+1]
				}
			}
		}
		if f[0] == "dnat" && len(f) >= 3 {
			r.Proto, r.Port = f[1], f[2] // dnat <proto> <port> to ...
		}
	case "ingress":
		// accept|drop <target> [proto] [port] [log]
		r.Action, r.Target = f[0], f[1]
		i := 2
		switch {
		case i < len(f) && isProtoTok(f[i]):
			r.Proto = f[i]
			i++
			if i < len(f) && f[i] != "log" {
				r.Port = f[i]
				i++
			}
		}
		if i < len(f) && f[i] == "log" {
			r.Log = true
		}
	default: // filter
		r.Action, r.Dir, r.Proto, r.Port, r.Target = f[0], f[1], f[2], f[3], f[4]
		for i := 5; i < len(f); i++ {
			if f[i] == "on" && i+1 < len(f) {
				r.Iface = f[i+1]
			} else if f[i] == "log" {
				r.Log = true
			}
		}
	}
	return r
}

func parseDraftRules(text string) ([]*draftRule, []string) {
	var rules []*draftRule
	var trivia []string
	id := 0
	lines := strings.Split(text, "\n")
	// Drop the final empty element that a trailing newline produces, so a
	// round-trip (serialize always ends each line with "\n") is stable and does
	// not accumulate blank lines at EOF.
	if n := len(lines); n > 0 && lines[n-1] == "" {
		lines = lines[:n-1]
	}
	for _, raw := range lines {
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
			if f, body, comment, kind, ok := ruleFields(strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))); ok {
				rules = append(rules, mkDraftRule(id, true, f, body, comment, kind, trivia))
				id++
				trivia = nil
				continue
			}
		} else if f, body, comment, kind, ok := ruleFields(trimmed); ok {
			rules = append(rules, mkDraftRule(id, false, f, body, comment, kind, trivia))
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

// annotateDraft fills live hit counts for enabled rules via the engine's per-rule
// comment (ctr from ruleCounters, computed once by the caller).
func annotateDraft(rules []*draftRule, ctr map[string]int64) {
	var prs []PolicyRule
	var idx []int
	for i, r := range rules {
		// nat/zone rules carry no "nftgeo:" counter comment, so they never match.
		if r.Disabled || r.Kind == "section" || r.Kind == "nat" || r.Kind == "zone" || r.Kind == "synproxy" {
			continue
		}
		prs = append(prs, PolicyRule{Action: r.Action, Dir: r.Dir, Proto: r.Proto, Port: r.Port, Target: r.Target, Iface: r.Iface})
		idx = append(idx, i)
	}
	annotate(prs, ctr)
	for k, pr := range prs {
		rules[idx[k]].Hits = pr.Hits
		rules[idx[k]].Matched = pr.Matched
	}
}

// reqRuleFile resolves the "file" field of a request; writes a 400 and returns
// nil for an unknown file.
func reqRuleFile(w http.ResponseWriter, rel string) *ruleFile {
	rf := findRuleFile(rel)
	if rf == nil {
		http.Error(w, `{"error":"unknown rule file"}`, http.StatusBadRequest)
	}
	return rf
}

// handleRulesDraft returns the parsed rules across every editable file
// (rules.conf + rules.d/*.conf, in engine order), each tagged with its file.
func cliDraftRules() []*draftRule {
	ctr := ruleCounters()
	var all []*draftRule
	for _, rf := range ruleFileList() {
		items, _ := parseDraftRules(draftTextFor(rf))
		annotateDraft(items, ctr)
		for _, it := range items {
			it.File = rf.rel // needed so the TUI's mutations know their file
		}
		all = append(all, items...)
	}
	return all
}

func handleRulesDraft(w http.ResponseWriter, r *http.Request) {
	ctr := ruleCounters()
	all := []*draftRule{}
	var files []map[string]interface{}
	for _, rf := range ruleFileList() {
		items, _ := parseDraftRules(draftTextFor(rf))
		annotateDraft(items, ctr)
		for _, it := range items {
			it.File = rf.rel
			all = append(all, it)
		}
		_, hasDraft := os.Stat(rf.draft)
		files = append(files, map[string]interface{}{"name": rf.rel, "hasDraft": hasDraft == nil})
	}
	writeJSONCached(w, r, map[string]interface{}{"files": files, "rules": all})
}

func findRuleFileByRel(rel string) *ruleFile {
	for _, rf := range ruleFileList() {
		if rf.rel == rel {
			return &rf
		}
	}
	return nil
}

// toggleRuleDraft flips a draft rule's disabled state and saves the draft.
// Single toggle path shared by the web handler and the console TUI; sections
// cannot be toggled. Same errMsg/code convention as writeObjectsDraft.
func toggleRuleDraft(fileID string, id int) (disabled bool, errMsg string, code int) {
	rf := findRuleFileByRel(fileID)
	if rf == nil {
		return false, "unknown rule file", http.StatusBadRequest
	}
	rules, tail := parseDraftRules(draftTextFor(*rf))
	var found *draftRule
	for _, rr := range rules {
		if rr.ID == id {
			found = rr
		}
	}
	if found == nil || found.Kind == "section" {
		return false, "no such rule", http.StatusBadRequest
	}
	found.Disabled = !found.Disabled
	if err := writeDraftFor(*rf, rules, tail); err != nil {
		return false, "cannot write draft", http.StatusInternalServerError
	}
	return found.Disabled, "", 0
}

// moveRuleDraft moves a draft rule to a new index, within one file or across
// files. Single move path shared by the web handler (cross-file) and the
// console TUI (both); same errMsg/code convention as writeObjectsDraft.
func moveRuleDraft(fromFileID, toFileID string, fromID, toIndex int) (errMsg string, code int) {
	fromRf := findRuleFileByRel(fromFileID)
	toRf := findRuleFileByRel(toFileID)
	if fromRf == nil || toRf == nil {
		return "unknown rule file", http.StatusBadRequest
	}
	fromRules, fromTail := parseDraftRules(draftTextFor(*fromRf))
	toRules, toTail := parseDraftRules(draftTextFor(*toRf))

	var moved *draftRule
	var kept []*draftRule
	for _, rr := range fromRules {
		if rr.ID == fromID && moved == nil {
			moved = rr
		} else {
			kept = append(kept, rr)
		}
	}
	if moved == nil {
		return "rule not found in source file", http.StatusBadRequest
	}
	moved.File = toRf.rel

	if fromFileID == toFileID {
		if toIndex < 0 || toIndex > len(kept) {
			toIndex = len(kept)
		}
		newRules := append(kept[:toIndex], append([]*draftRule{moved}, kept[toIndex:]...)...)
		if err := writeDraftFor(*fromRf, newRules, fromTail); err != nil {
			return "cannot write draft", http.StatusInternalServerError
		}
		return "", 0
	}

	if err := writeDraftFor(*fromRf, kept, fromTail); err != nil {
		return "cannot write source draft", http.StatusInternalServerError
	}
	if toIndex < 0 || toIndex > len(toRules) {
		toIndex = len(toRules)
	}
	newTo := make([]*draftRule, 0, len(toRules)+1)
	newTo = append(newTo, toRules[:toIndex]...)
	newTo = append(newTo, moved)
	newTo = append(newTo, toRules[toIndex:]...)
	if err := writeDraftFor(*toRf, newTo, toTail); err != nil {
		return "cannot write destination draft", http.StatusInternalServerError
	}
	return "", 0
}

func handleRulesReorder(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File  string `json:"file"`
		Order []int  `json:"order"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	rf := reqRuleFile(w, req.File)
	if rf == nil {
		return
	}
	rules, tail := parseDraftRules(draftTextFor(*rf))
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
	if err := writeDraftFor(*rf, nr, tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true})
}

// handleRulesMove moves a single rule from one file to another at a position,
// so the UI can reorder rules across the numbered files (rules.conf, rules.d/*)
// which the engine evaluates in that global file order. Within a file, use
// /reorder instead.
func handleRulesMove(w http.ResponseWriter, r *http.Request) {
	var req struct {
		FromFile string `json:"fromFile"`
		FromID   int    `json:"fromId"`
		ToFile   string `json:"toFile"`
		ToIndex  int    `json:"toIndex"` // insert position among toFile's items; <0 or too large = end
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	if req.FromFile == req.ToFile {
		http.Error(w, `{"error":"same file — use reorder"}`, http.StatusBadRequest)
		return
	}
	if errMsg, code := moveRuleDraft(req.FromFile, req.ToFile, req.FromID, req.ToIndex); errMsg != "" {
		http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true})
}

func handleRulesToggle(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File string `json:"file"`
		ID   int    `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	disabled, errMsg, code := toggleRuleDraft(req.File, req.ID)
	if errMsg != "" {
		http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true, "disabled": disabled})
}

// handleRulesToggleLog flips per-rule connection logging on a filter rule by
// adding/removing the trailing "log" token in its verbatim body.
// ruleFileNameRe validates a new rules.d drop-in name (without the .conf).
// Sorted filename order controls engine precedence, so numeric prefixes like
// "50-web" are typical; keep it to safe path-free characters.
var ruleFileNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// handleRulesFileCreate creates a new empty rules.d/<name>.conf so rules can be
// organised across files from the dashboard. The file is empty (just a header),
// so it has no effect on the ruleset until rules are added to it via the draft.
func handleRulesFileCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	name = strings.TrimSuffix(name, ".conf")
	if !ruleFileNameRe.MatchString(name) {
		http.Error(w, `{"error":"invalid file name (letters, digits, . _ - only, e.g. 50-web)"}`, http.StatusBadRequest)
		return
	}
	rel := "rules.d/" + name + ".conf"
	if findRuleFile(rel) != nil {
		http.Error(w, `{"error":"a file with that name already exists"}`, http.StatusBadRequest)
		return
	}
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		http.Error(w, `{"error":"cannot create rules.d"}`, http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(filepath.Join(rulesDir, name+".conf"), []byte("# "+name+"\n"), 0o644); err != nil {
		http.Error(w, `{"error":"cannot write file"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"created": true, "name": rel})
}

func handleRulesToggleLog(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File string `json:"file"`
		ID   int    `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	rf := reqRuleFile(w, req.File)
	if rf == nil {
		return
	}
	rules, tail := parseDraftRules(draftTextFor(*rf))
	var found *draftRule
	for _, rr := range rules {
		if rr.ID == req.ID {
			found = rr
		}
	}
	if found == nil || (found.Kind != "filter" && found.Kind != "ingress") {
		http.Error(w, `{"error":"log toggle only applies to filter/ingress rules"}`, http.StatusBadRequest)
		return
	}
	fields := strings.Fields(found.Body)
	out := fields[:0]
	for _, tok := range fields {
		if tok != "log" {
			out = append(out, tok)
		}
	}
	if found.Log {
		found.Log = false
		found.Body = strings.Join(out, " ")
	} else {
		found.Log = true
		found.Body = strings.Join(out, " ") + " log"
	}
	if err := writeDraftFor(*rf, rules, tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true, "log": found.Log})
}

// handleRulesSection adds a new section header (no id) or renames one (with id).
func handleRulesSection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File  string `json:"file"`
		ID    *int   `json:"id"`
		Title string `json:"title"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	rf := reqRuleFile(w, req.File)
	if rf == nil {
		return
	}
	title := sanitizeComment(req.Title)
	if title == "" {
		http.Error(w, `{"error":"section needs a title"}`, http.StatusBadRequest)
		return
	}
	rules, tail := parseDraftRules(draftTextFor(*rf))
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
	if err := writeDraftFor(*rf, rules, tail); err != nil {
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
		{ID: "mail-server", Name: "Mail Server", Builtin: true,
			Description: "Allow SMTP/IMAP from anywhere and block known abuse both ways.",
			Lines:       []string{"## Mail server", "allow in tcp 25,465,587 any # smtp", "allow in tcp 993 any # imaps", "deny in any - abuse # abuse in", "deny out any - abuse # abuse out"}},
		{ID: "wireguard", Name: "WireGuard Endpoint", Builtin: true,
			Description: "Allow WireGuard UDP and SSH from a trusted admin subnet (edit target).",
			Lines:       []string{"## WireGuard", "allow in udp 51820 any # wireguard", "allow in tcp 22 10.0.0.0/8 # admin ssh", "deny in any - abuse # abuse in"}},
		{ID: "ssh-lockdown", Name: "SSH Lockdown", Builtin: true,
			Description: "SSH only from a named admin group/object (create GROUP_ADMINS first).",
			Lines:       []string{"## SSH lockdown", "allow in tcp 22 ADMINS # admin ssh", "deny in any - abuse # abuse in", "deny out any - abuse # abuse out"}},
		{ID: "nginx", Name: "Nginx Web Server", Builtin: true,
			Description: "Nginx HTTP/HTTPS with abuse filtering and SSH admin access.",
			Lines:       []string{"## Nginx", "allow in tcp 80 any # http", "allow in tcp 443 any # https", "allow in tcp 22 ADMINS # admin ssh", "deny in any - abuse # abuse in", "deny out any - abuse # abuse out"}},
		{ID: "kamailio", Name: "Kamailio SIP Server", Builtin: true,
			Description: "Kamailio SIP/SIPS ports from a trusted region (edit geo). Includes RTP range.",
			Lines:       []string{"## Kamailio SIP", "allow in udp 5060 europe # sip-udp", "allow in tcp 5060 europe # sip-tcp", "allow in tcp 5061 europe # sips-tls", "allow in udp 10000-20000 europe # rtp-range", "deny in any - abuse # abuse in"}},
		{ID: "redis", Name: "Redis Server", Builtin: true,
			Description: "Redis locked to an admin group (never expose to the world).",
			Lines:       []string{"## Redis", "allow in tcp 6379 ADMINS # redis", "deny in any - abuse # abuse in"}},
		{ID: "postgres", Name: "PostgreSQL Server", Builtin: true,
			Description: "PostgreSQL from a named app/admin group only.",
			Lines:       []string{"## PostgreSQL", "allow in tcp 5432 ADMINS # postgres", "deny in any - abuse # abuse in"}},
		{ID: "mysql", Name: "MySQL/MariaDB Server", Builtin: true,
			Description: "MySQL/MariaDB from a named admin group only.",
			Lines:       []string{"## MySQL", "allow in tcp 3306 ADMINS # mysql", "deny in any - abuse # abuse in"}},
		{ID: "gitlab", Name: "GitLab Server", Builtin: true,
			Description: "GitLab HTTP/HTTPS/SSH with abuse filtering.",
			Lines:       []string{"## GitLab", "allow in tcp 80 any # http", "allow in tcp 443 any # https", "allow in tcp 22 ADMINS # git-ssh", "deny in any - abuse # abuse in", "deny out any - abuse # abuse out"}},
		{ID: "docker-registry", Name: "Docker Registry", Builtin: true,
			Description: "Private Docker registry from admin group only.",
			Lines:       []string{"## Docker Registry", "allow in tcp 5000 ADMINS # registry", "deny in any - abuse # abuse in"}},
		{ID: "elasticsearch", Name: "Elasticsearch", Builtin: true,
			Description: "Elasticsearch HTTP (9200) + transport (9300) from app group only.",
			Lines:       []string{"## Elasticsearch", "allow in tcp 9200 APPS # es-http", "allow in tcp 9300 APPS # es-transport", "deny in any - abuse # abuse in"}},
		{ID: "grafana", Name: "Grafana Dashboard", Builtin: true,
			Description: "Grafana from a named admin group (edit target).",
			Lines:       []string{"## Grafana", "allow in tcp 3000 ADMINS # grafana", "deny in any - abuse # abuse in"}},
		{ID: "dns-server", Name: "DNS Server (BIND/unbound)", Builtin: true,
			Description: "DNS TCP+UDP from anywhere (recursive) or edit target to restrict.",
			Lines:       []string{"## DNS Server", "allow in tcp 53 any # dns-tcp", "allow in udp 53 any # dns-udp", "deny in any - abuse # abuse in"}},
		{ID: "openvpn", Name: "OpenVPN Server", Builtin: true,
			Description: "OpenVPN UDP 1194 + SSH admin from a trusted subnet.",
			Lines:       []string{"## OpenVPN", "allow in udp 1194 any # openvpn", "allow in tcp 22 ADMINS # admin ssh", "deny in any - abuse # abuse in"}},
		{ID: "minecraft", Name: "Minecraft Server", Builtin: true,
			Description: "Minecraft Java port + RCON from admin group.",
			Lines:       []string{"## Minecraft", "allow in tcp 25565 any # minecraft", "allow in tcp 25575 ADMINS # rcon", "deny in any - abuse # abuse in"}},
		{ID: "mosh", Name: "Mosh Shell", Builtin: true,
			Description: "Mosh UDP range 60000-61000 + SSH from admin group.",
			Lines:       []string{"## Mosh", "allow in tcp 22 ADMINS # ssh", "allow in udp 60000-61000 ADMINS # mosh", "deny in any - abuse # abuse in"}},
		{ID: "prometheus-stack", Name: "Prometheus + Grafana", Builtin: true,
			Description: "Prometheus (9090) + Grafana (3000) from monitoring group only.",
			Lines:       []string{"## Prometheus Stack", "allow in tcp 9090 MONITORING # prometheus", "allow in tcp 3000 MONITORING # grafana", "deny in any - abuse # abuse in"}},
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

// currentTemplateLines snapshots the whole policy (every rule file, draft-or-live)
// as clean template lines (rule bodies + section headers, without blank/comment
// trivia).
func currentTemplateLines() []string {
	var lines []string
	for _, rf := range ruleFileList() {
		items, _ := parseDraftRules(draftTextFor(rf))
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
		writeJSONCached(w, r, append(builtinTemplates(), loadSavedTemplates()...))
	case http.MethodPost:
		var req struct{ Name, Description string }
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
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
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
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

// handleRulesImport prepends a template's rules/sections to a file's draft (they
// still need a Commit to deploy).
func handleRulesImport(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File string `json:"file"`
		ID   string `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	rf := reqRuleFile(w, req.File)
	if rf == nil {
		return
	}
	tpl := findTemplate(req.ID)
	if tpl == nil {
		http.Error(w, `{"error":"no such template"}`, http.StatusBadRequest)
		return
	}
	tplItems, _ := parseDraftRules(strings.Join(tpl.Lines, "\n"))
	cur, tail := parseDraftRules(draftTextFor(*rf))
	if err := writeDraftFor(*rf, append(tplItems, cur...), tail); err != nil {
		http.Error(w, `{"error":"cannot write draft"}`, http.StatusInternalServerError)
		return
	}
	// Warn when a template references a group target that isn't defined yet
	// (issue #38). Templates use uppercase placeholders like ADMINS/APPS.
	defined := map[string]bool{}
	for _, name := range definedGroupNames() {
		defined[strings.ToUpper(name)] = true
	}
	var warnings []string
	seen := map[string]bool{}
	for _, line := range tpl.Lines {
		fields := strings.Fields(line)
		if len(fields) < 5 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		target := fields[4]
		// Skip country codes, IP/CIDR, any/abuse/-, and lowercase (real) names.
		if target == "" || len(target) == 2 || strings.Contains(target, ".") ||
			target == "any" || target == "abuse" || target == "-" ||
			strings.ToUpper(target) != target {
			continue
		}
		if !defined[strings.ToUpper(target)] && !seen[target] {
			seen[target] = true
			warnings = append(warnings, "Template references undefined group '"+target+
				"'. Create GROUP_"+strings.ToUpper(target)+" in Objects before committing.")
		}
	}
	resp := map[string]interface{}{"imported": true, "rules": len(tplItems)}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	writeJSON(w, resp)
}

// definedGroupNames returns every GROUP_ name from config + the objects drop-in
// (live and draft), so template import can flag references to groups that don't
// exist yet.
func definedGroupNames() []string {
	seen := map[string]bool{}
	var names []string
	for _, f := range []string{configFile, objLiveFile, objDraftFile} {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "GROUP_") {
				continue
			}
			eq := strings.Index(line, "=")
			if eq < 0 {
				continue
			}
			name := strings.TrimSpace(line[6:eq])
			if name != "" && !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
		}
	}
	return names
}

// ---- rule add / edit / delete (M6B.4) ----

var (
	// a number, range, comma list, a SERVICE_ name (letters), or a /proto-tagged
	// port (53/udp) - the engine resolves and re-validates, so this is permissive
	// but still free of shell metacharacters.
	rulePortRe   = regexp.MustCompile(`^[A-Za-z0-9_,/-]+$`)
	ruleTargetRe = regexp.MustCompile(`^[A-Za-z0-9_.:/-]+$`)
	ruleIfaceRe  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	ruleProtos   = map[string]bool{"tcp": true, "udp": true, "sctp": true, "all": true, "any": true, "icmp": true, "icmpv6": true}

	// NAT / zone drawers (permissive; the engine's validate is the final gate).
	zoneNameRe  = regexp.MustCompile(`^[a-z0-9_]+$`)                                                                             // ZONE_<NAME> -> lowercase key
	natAddrRe   = regexp.MustCompile(`^([0-9]{1,3}(\.[0-9]{1,3}){3}|[0-9a-fA-F:]+)$`)                                            // snat: a bare IP
	natTargetRe = regexp.MustCompile(`^(\[[0-9a-fA-F:]+\]:[0-9]{1,5}|[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]{1,5})?|[0-9a-fA-F:]+)$`) // dnat: ip[:port] / [v6]:port
	natPortRe   = regexp.MustCompile(`^[0-9]{1,5}$`)

	throttlePortRe = regexp.MustCompile(`^[0-9]+(-[0-9]+)?(,[0-9]+(-[0-9]+)?)*$`)
	throttleRateRe = regexp.MustCompile(`^[0-9]+/(second|minute|hour)$`)
	throttleBanRe  = regexp.MustCompile(`^[0-9]+[smhd]$`)
)

// buildThrottleBody assembles/validates a throttle rule; the engine re-validates
// at preview/deploy.
func buildThrottleBody(dir, proto, port, rate, ban, iface string) (string, error) {
	dir, proto = strings.TrimSpace(dir), strings.ToLower(strings.TrimSpace(proto))
	port, rate = strings.TrimSpace(port), strings.TrimSpace(rate)
	ban, iface = strings.TrimSpace(ban), strings.TrimSpace(iface)
	switch dir {
	case "in", "fwd-in":
	default:
		return "", fmt.Errorf("throttle direction must be in or fwd-in")
	}
	switch proto {
	case "tcp", "udp":
	default:
		return "", fmt.Errorf("throttle protocol must be tcp or udp")
	}
	if !throttlePortRe.MatchString(port) {
		return "", fmt.Errorf("throttle port must be a number, range or list")
	}
	if !throttleRateRe.MatchString(rate) {
		return "", fmt.Errorf("rate must be like 5/minute (N/second|minute|hour)")
	}
	parts := []string{"throttle", dir, proto, port, rate}
	if ban != "" {
		if !throttleBanRe.MatchString(ban) {
			return "", fmt.Errorf("ban must be like 30m, 1h or 2d")
		}
		parts = append(parts, "ban", ban)
	}
	if iface != "" {
		if !ruleIfaceRe.MatchString(iface) {
			return "", fmt.Errorf("invalid interface name")
		}
		parts = append(parts, "on", iface)
	}
	return strings.Join(parts, " "), nil
}

// buildSynproxyBody assembles/validates a synproxy rule
// (synproxy <in|fwd-in> tcp <port> [on <iface>]); the engine re-validates.
func buildSynproxyBody(dir, port, iface string) (string, error) {
	dir, port, iface = strings.TrimSpace(dir), strings.TrimSpace(port), strings.TrimSpace(iface)
	switch dir {
	case "in", "fwd-in":
	default:
		return "", fmt.Errorf("synproxy direction must be in or fwd-in")
	}
	if !throttlePortRe.MatchString(port) {
		return "", fmt.Errorf("synproxy port must be a number, range or list")
	}
	parts := []string{"synproxy", dir, "tcp", port}
	if iface != "" {
		if !ruleIfaceRe.MatchString(iface) {
			return "", fmt.Errorf("invalid interface name")
		}
		parts = append(parts, "on", iface)
	}
	return strings.Join(parts, " "), nil
}

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
		return "", fmt.Errorf("protocol must be tcp / udp / sctp / all / any / icmp / icmpv6")
	}
	switch proto {
	case "icmp", "icmpv6":
		port = "-" // port-less protocols
	default:
		if port == "" {
			// Empty port = every port of this protocol ("any -" = every
			// protocol/port; "tcp -" = all TCP via meta l4proto).
			port = "-"
		}
	}
	if port != "-" && !rulePortRe.MatchString(port) {
		return "", fmt.Errorf("port must be a number, range (n-m), list (n,m), or a service")
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

// buildIngressBody assembles/validates an ingress-hook rule
// (accept|drop <target> [proto] [port] [log]); the engine re-validates on apply.
func buildIngressBody(action, target, proto, port string, log bool) (string, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	target = strings.TrimSpace(target)
	proto = strings.ToLower(strings.TrimSpace(proto))
	port = strings.TrimSpace(port)
	if action != "accept" && action != "drop" {
		return "", fmt.Errorf("ingress action must be accept or drop")
	}
	if target == "" {
		return "", fmt.Errorf("target required (country / region / group / IP / CIDR / any / abuse)")
	}
	if !ruleTargetRe.MatchString(target) {
		return "", fmt.Errorf("target: country / region / group / IP / CIDR / any / abuse")
	}
	if action == "accept" && target == "abuse" {
		return "", fmt.Errorf("target 'abuse' only valid with drop")
	}
	parts := []string{action, target}
	if proto != "" && proto != "any" {
		if !ruleProtos[proto] {
			return "", fmt.Errorf("protocol must be tcp / udp / sctp / all / any / icmp / icmpv6")
		}
		parts = append(parts, proto)
		if port != "" && port != "-" {
			if !rulePortRe.MatchString(port) {
				return "", fmt.Errorf("port must be a number, range (n-m), list (n,m), or a service")
			}
			parts = append(parts, port)
		}
	} else if port != "" && port != "-" {
		return "", fmt.Errorf("choose a protocol (tcp/udp/…) to match a port")
	}
	if log {
		parts = append(parts, "log")
	}
	return strings.Join(parts, " "), nil
}

// buildZoneBody assembles/validates an inter-zone rule
// (allow|deny <src> -> <dst> <proto> <port> [from <geo>]); engine re-validates.
func buildZoneBody(action, src, dst, proto, port, geo string) (string, error) {
	action = strings.ToLower(strings.TrimSpace(action))
	src, dst = strings.ToLower(strings.TrimSpace(src)), strings.ToLower(strings.TrimSpace(dst))
	proto, port, geo = strings.ToLower(strings.TrimSpace(proto)), strings.TrimSpace(port), strings.TrimSpace(geo)
	if action != "allow" && action != "deny" {
		return "", fmt.Errorf("action must be allow or deny")
	}
	for _, z := range []string{src, dst} {
		if z != "any" && !zoneNameRe.MatchString(z) {
			return "", fmt.Errorf("zone names are letters/digits/underscore, or 'any'")
		}
	}
	if !ruleProtos[proto] {
		return "", fmt.Errorf("protocol must be tcp / udp / sctp / all / any / icmp / icmpv6")
	}
	switch proto {
	case "icmp", "icmpv6", "any":
		if port == "" {
			port = "-"
		}
	default:
		if port == "" {
			return "", fmt.Errorf("proto %s needs a port or service", proto)
		}
	}
	if port != "-" && !rulePortRe.MatchString(port) {
		return "", fmt.Errorf("port must be a number, range, list, or a service")
	}
	parts := []string{action, src, "->", dst, proto, port}
	if geo != "" {
		if !ruleTargetRe.MatchString(geo) {
			return "", fmt.Errorf("from: country / region / group / IP / CIDR")
		}
		parts = append(parts, "from", geo)
	}
	return strings.Join(parts, " "), nil
}

// buildNatBody assembles/validates a NAT rule (masquerade / snat / dnat); the
// engine re-validates, so this is permissive but shell-metacharacter-free. lan
// is the optional inbound interface for masquerade/snat ("in <lan>").
func buildNatBody(natType, proto, port, target, geo, iface, lan string) (string, error) {
	natType = strings.ToLower(strings.TrimSpace(natType))
	target, iface, lan = strings.TrimSpace(target), strings.TrimSpace(iface), strings.TrimSpace(lan)
	if iface != "" && !ruleIfaceRe.MatchString(iface) {
		return "", fmt.Errorf("invalid interface name")
	}
	if lan != "" && !ruleIfaceRe.MatchString(lan) {
		return "", fmt.Errorf("invalid LAN interface name")
	}
	lanSuffix := ""
	if lan != "" {
		lanSuffix = " in " + lan
	}
	switch natType {
	case "masquerade":
		if iface == "" {
			return "", fmt.Errorf("masquerade needs a WAN interface")
		}
		return "masquerade on " + iface + lanSuffix, nil
	case "snat":
		if iface == "" {
			return "", fmt.Errorf("snat needs a WAN interface")
		}
		if !natAddrRe.MatchString(target) {
			return "", fmt.Errorf("snat target must be an IP address")
		}
		return "snat out on " + iface + " to " + target + lanSuffix, nil
	case "dnat":
		proto, port, geo = strings.ToLower(strings.TrimSpace(proto)), strings.TrimSpace(port), strings.TrimSpace(geo)
		if proto != "tcp" && proto != "udp" {
			return "", fmt.Errorf("dnat protocol must be tcp or udp")
		}
		if !natPortRe.MatchString(port) {
			return "", fmt.Errorf("dnat port must be a single number")
		}
		if !natTargetRe.MatchString(target) {
			return "", fmt.Errorf("dnat target must be an IP or ip:port")
		}
		parts := []string{"dnat", proto, port, "to", target}
		if geo != "" {
			if !ruleTargetRe.MatchString(geo) {
				return "", fmt.Errorf("from: country / region / group / IP")
			}
			parts = append(parts, "from", geo)
		}
		if iface != "" {
			parts = append(parts, "on", iface)
		}
		return strings.Join(parts, " "), nil
	}
	return "", fmt.Errorf("nat type must be masquerade / snat / dnat")
}

// ruleSaveReq mirrors the web's /api/rules/draft/save request body; the
// console TUI's rule forms build the same struct so both paths share
// saveRuleDraft. ID nil = append a new rule, else edit that rule in place.
type ruleSaveReq struct {
	File                                    string
	ID                                      *int
	Kind                                    string
	Action, Dir, Proto, Port, Target, Iface string
	Src, Dst, Geo, NatType, Lan             string
	Rate, Ban                               string
	Name                                    string
	Log                                     bool
}

// saveRuleDraft builds the rule body for the request's kind (via the same
// build*Body validators the web uses) and appends or edits it in the file's
// draft. Single rule-save path shared by the web handler and the console TUI;
// same errMsg/code convention as writeObjectsDraft.
func saveRuleDraft(req ruleSaveReq) (errMsg string, code int) {
	rf := findRuleFileByRel(req.File)
	if rf == nil {
		return "unknown rule file", http.StatusBadRequest
	}
	var body string
	var err error
	switch {
	case req.Kind == "zone":
		body, err = buildZoneBody(req.Action, req.Src, req.Dst, req.Proto, req.Port, req.Geo)
	case req.Kind == "nat":
		body, err = buildNatBody(req.NatType, req.Proto, req.Port, req.Target, req.Geo, req.Iface, req.Lan)
	case req.Kind == "ingress":
		body, err = buildIngressBody(req.Action, req.Target, req.Proto, req.Port, req.Log)
	case req.Kind == "synproxy":
		body, err = buildSynproxyBody(req.Dir, req.Port, req.Iface)
	case req.Action == "throttle":
		body, err = buildThrottleBody(req.Dir, req.Proto, req.Port, req.Rate, req.Ban, req.Iface)
	default:
		body, err = buildRuleBody(req.Action, req.Dir, req.Proto, req.Port, req.Target, req.Iface)
		if err == nil && req.Log {
			body += " log"
		}
	}
	if err != nil {
		return err.Error(), http.StatusBadRequest
	}
	name := sanitizeComment(req.Name)
	rules, tail := parseDraftRules(draftTextFor(*rf))
	if req.ID != nil {
		var found *draftRule
		for _, rr := range rules {
			if rr.ID == *req.ID {
				found = rr
			}
		}
		if found == nil {
			return "no such rule", http.StatusBadRequest
		}
		found.Body, found.Name = body, name
	} else {
		rules = append(rules, &draftRule{ID: -1, Body: body, Name: name})
	}
	if err := writeDraftFor(*rf, rules, tail); err != nil {
		return "cannot write draft", http.StatusInternalServerError
	}
	return "", 0
}

func handleRulesSave(w http.ResponseWriter, r *http.Request) {
	var req ruleSaveReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	if errMsg, code := saveRuleDraft(req); errMsg != "" {
		http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
		return
	}
	writeJSON(w, map[string]interface{}{"saved": true})
}

// deleteRuleDraft removes a rule from the file's draft, preserving its leading
// comments/blanks with the following rule (or the file tail) so section
// headers survive. Single delete path shared by the web handler and the
// console TUI; same errMsg/code convention as writeObjectsDraft.
func deleteRuleDraft(fileID string, id int) (errMsg string, code int) {
	rf := findRuleFileByRel(fileID)
	if rf == nil {
		return "unknown rule file", http.StatusBadRequest
	}
	rules, tail := parseDraftRules(draftTextFor(*rf))
	idx := -1
	for i, rr := range rules {
		if rr.ID == id {
			idx = i
		}
	}
	if idx < 0 {
		return "no such rule", http.StatusBadRequest
	}
	trivia := rules[idx].Trivia
	if idx+1 < len(rules) {
		rules[idx+1].Trivia = append(append([]string{}, trivia...), rules[idx+1].Trivia...)
	} else {
		tail = append(append([]string{}, trivia...), tail...)
	}
	rules = append(rules[:idx], rules[idx+1:]...)
	if err := writeDraftFor(*rf, rules, tail); err != nil {
		return "cannot write draft", http.StatusInternalServerError
	}
	return "", 0
}

func handleRulesDelete(w http.ResponseWriter, r *http.Request) {
	var req struct {
		File string `json:"file"`
		ID   int    `json:"id"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
		return
	}
	if errMsg, code := deleteRuleDraft(req.File, req.ID); errMsg != "" {
		http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
		return
	}
	writeJSON(w, map[string]interface{}{"deleted": true})
}

// ---- commit pipeline (all stages) ----

// commitPreviewInfo validates the assembled draft and returns the preview
// payload (validate output + plan). Single preview path shared by the web
// handler and the console TUI; same errMsg/code convention as
// writeObjectsDraft.
func commitPreviewInfo() (payload map[string]interface{}, errMsg string, code int) {
	if len(activeStages()) == 0 {
		return nil, "no draft to preview", http.StatusBadRequest
	}
	msg, ok := validateDraft()
	if !ok {
		return map[string]interface{}{"valid": false, "message": msg}, "", 0
	}
	envv, cl := previewEnv()
	defer cl()
	plan, _ := runEnv(envv, nftgeoBin, "plan")
	return map[string]interface{}{"valid": true, "message": msg, "plan": strings.TrimSpace(plan)}, "", 0
}

func handleCommitPreview(w http.ResponseWriter, r *http.Request) {
	payload, errMsg, code := commitPreviewInfo()
	if errMsg != "" {
		http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
		return
	}
	writeJSON(w, payload)
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

// clampDeadman maps a requested confirm window to the allowed 20-600s range,
// defaulting to 90s for anything out of range (including 0/unset).
func clampDeadman(t int) int {
	if t < 20 || t > 600 {
		return 90
	}
	return t
}

// commitApply runs the deadman deploy: validate the assembled draft, back up
// every live file, promote each draft, then `apply --confirm <T>` and start
// the deadman watcher. Single deploy path shared by the web handler and the
// console TUI; same errMsg/code convention as writeObjectsDraft (validation
// and apply failures are 200 payloads with deployed=false, matching the web
// contract).
func commitApply(seconds int) (payload map[string]interface{}, errMsg string, code int) {
	commitMu.Lock()
	defer commitMu.Unlock()
	if pending.active {
		return nil, "a deploy is already pending; keep or roll it back first", http.StatusConflict
	}
	if _, err := os.Stat(sentinel); err == nil {
		return nil, "a confirm is already pending on the host", http.StatusConflict
	}
	act := activeStages()
	if len(act) == 0 {
		return nil, "no draft to deploy", http.StatusBadRequest
	}
	// Never deploy an invalid ruleset - validate the draft before touching live.
	if msg, ok := validateDraft(); !ok {
		return map[string]interface{}{"deployed": false, "valid": false, "message": msg}, "", 0
	}
	T := clampDeadman(seconds)
	// Back up every live file, promote each draft, then apply with the deadman.
	for _, s := range act {
		if err := backupLive(s); err != nil {
			restoreBackups()
			return nil, "cannot back up live files", http.StatusInternalServerError
		}
	}
	for _, s := range act {
		if err := copyFile(s.draft, s.live); err != nil {
			restoreBackups()
			return nil, "cannot stage draft to live", http.StatusInternalServerError
		}
	}
	out, err := run(nftgeoBin, "apply", "--confirm", strconv.Itoa(T))
	if err != nil {
		restoreBackups()
		return map[string]interface{}{"deployed": false, "message": strings.TrimSpace(out)}, "", 0
	}
	pending.active = true
	pending.deadline = time.Now().Add(time.Duration(T) * time.Second)
	pending.seconds = T
	go watchDeadman(T)
	return map[string]interface{}{"deployed": true, "seconds": T, "message": strings.TrimSpace(out)}, "", 0
}

func handleCommitApply(w http.ResponseWriter, r *http.Request) {
	// Note: the request body is decoded before commitApply's guards run; the
	// original inline handler checked pending/sentinel/drafts first. The only
	// visible difference is which error a malformed body gets during a pending
	// deploy — no real client hits it.
	var req struct {
		Seconds int `json:"seconds"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req); err != nil {
		http.Error(w, `{"error":"bad request"}`, http.StatusBadRequest)
		return
	}
	payload, errMsg, code := commitApply(req.Seconds)
	if errMsg != "" {
		http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
		return
	}
	writeJSON(w, payload)
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

// commitKeep confirms the pending deploy (`apply --commit`) and clears every
// stage's draft and backup. Single keep path shared by the web handler and the
// console TUI; same errMsg/code convention as writeObjectsDraft.
func commitKeep() (payload map[string]interface{}, errMsg string, code int) {
	commitMu.Lock()
	defer commitMu.Unlock()
	out, err := run(nftgeoBin, "apply", "--commit")
	if err != nil {
		return nil, strings.TrimSpace(out), http.StatusInternalServerError
	}
	for _, s := range stages() {
		os.Remove(s.draft)
		os.Remove(s.backup)
	}
	pending.active = false
	return map[string]interface{}{"kept": true, "message": strings.TrimSpace(out)}, "", 0
}

func handleCommitKeep(w http.ResponseWriter, r *http.Request) {
	payload, errMsg, code := commitKeep()
	if errMsg != "" {
		http.Error(w, `{"error":`+strconv.Quote(errMsg)+`}`, code)
		return
	}
	writeJSON(w, payload)
}

// commitRollback reverts the pending deploy: engine rollback + restore the
// pre-apply file backups. Drafts are kept so the operator can fix and retry.
// Single rollback path shared by the web handler and the console TUI.
func commitRollback() map[string]interface{} {
	commitMu.Lock()
	defer commitMu.Unlock()
	out, _ := run(nftgeoBin, "rollback")
	restoreBackups()
	pending.active = false
	return map[string]interface{}{"rolledBack": true, "message": strings.TrimSpace(out)}
}

func handleCommitRollback(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, commitRollback())
}

// reconcileCommit recovers a deploy interrupted by a UI restart: leftover
// backups with no pending sentinel mean an apply was never kept, so restore the
// live files from their backups.
// reconcileBoot runs as ExecStartPre of nftgeo.service, before nftgeo-update
// loads the ruleset on boot. If an `apply --confirm` was interrupted by a
// reboot, the UI's pre-apply config backups still exist; restore them so the
// engine regenerates the *confirmed* (previous) config, not the unconfirmed one
// that was live when the box went down. Any sentinel present at boot is stale
// (its deadman died with the reboot), so clear it. Runs standalone (no server,
// no auth) — just file operations as root.
func reconcileBoot() {
	restored := false
	for _, s := range stages() {
		if _, err := os.Stat(s.backup); err == nil {
			copyFile(s.backup, s.live)
			os.Remove(s.backup)
			restored = true
		}
	}
	os.Remove(sentinel)
	if restored {
		log.Printf("nftgeo-ui: reconcile-boot rolled back an interrupted apply --confirm (restored config from backup)")
	}
}

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
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "cli":
			geo.load()
			startIfSampler()
			startNflog()
			// Load the persisted drop store so the TUI has 24h history (timeline,
			// top-IPs, KPIs) even when the live feed is unavailable — e.g. the web
			// service already holds the NFLOG group, or the kernel log is
			// unreadable in a container. Without this the dashboard is empty.
			loadStats()
			fs := flag.NewFlagSet("cli", flag.ExitOnError)
			refresh := fs.Duration("refresh", 5*time.Second, "live refresh interval (e.g. 2s, 5s, 10s, 0 to disable)")
			fs.Parse(os.Args[2:])
			startCLI(*refresh)
			return
		case "token":
			tokenCmd(os.Args[2:])
			return
		case "reconcile-boot":
			reconcileBoot()
			return
		}
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

	// Interface utilization sampler for the SOC overview (one /proc/net/dev
	// read per tick, in-memory ring only).
	startIfSampler()

	// NFLOG drop listener: works inside containers where the kernel log isn't
	// readable. When it's up, it records drops directly, so the journalctl-based
	// ingest below is skipped to avoid double-counting.
	startNflog()

	// Load persisted stats and start the ingest+dump ticker. Only write to disk
	// when new drops were actually ingested (no churn when the box is idle).
	loadStats()
	go func() {
		if nflogActive() {
			// NFLOG feeds the stats store as packets arrive; just persist
			// periodically so a restart keeps the history.
			for range time.Tick(5 * time.Minute) {
				dumpStats()
			}
			return
		}
		if ingestDropsLog() > 0 {
			dumpStats()
		}
		for range time.Tick(5 * time.Minute) {
			if ingestDropsLog() > 0 {
				dumpStats()
			}
		}
	}()

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
	http.HandleFunc("/api/session_poll", handleSessionPoll)

	api := func(pattern string, h http.HandlerFunc) { http.HandleFunc(pattern, requireAuth(h)) }

	api("/api/me", func(w http.ResponseWriter, r *http.Request) {
		sessMu.Lock()
		pending := false
		var expiresIn float64
		if pendingSession != nil && pendingSession.status == "pending" {
			pending = true
			expiresIn = pendingSession.expires.Sub(time.Now()).Seconds()
			if expiresIn < 0 {
				expiresIn = 0
				pendingSession.status = "accepted"
				pending = false
			}
		}
		sessMu.Unlock()
		writeJSON(w, map[string]interface{}{
			"mode":               w.Header().Get("X-Nftgeo-Mode"),
			"auth":               authOn,
			"pending_session":    pending,
			"pending_expires_in": expiresIn,
		})
	})

	api("/api/session_reject", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"POST only"}`, http.StatusMethodNotAllowed)
			return
		}
		sessMu.Lock()
		defer sessMu.Unlock()
		if pendingSession != nil && pendingSession.status == "pending" {
			pendingSession.status = "rejected"
			writeJSON(w, map[string]interface{}{"status": "rejected"})
			return
		}
		writeJSON(w, map[string]interface{}{"status": "none"})
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
		annotate(p, ruleCounters())
		writeJSONCached(w, r, p)
	})
	api("/api/baseline", func(w http.ResponseWriter, r *http.Request) {
		// Merge per-chain baseline counters with each chain's default policy, so
		// the Policy view can show what happens to unmatched packets.
		bc := baselineCounters()
		pol := chainPolicies()
		out := map[string]map[string]interface{}{}
		for hook, ctr := range bc {
			m := map[string]interface{}{}
			for k, v := range ctr {
				m[k] = v
			}
			out[hook] = m
		}
		for hook, p := range pol {
			if out[hook] == nil {
				out[hook] = map[string]interface{}{}
			}
			out[hook]["policy"] = p
		}
		// LOG_DROPS logs every drop globally, so the Policy view can show a deny
		// rule as effectively logged even when its per-rule flag is off.
		out["_meta"] = map[string]interface{}{"logDrops": logDropsOn()}
		writeJSON(w, out)
	})
	api("/api/alerts", func(w http.ResponseWriter, r *http.Request) {
		d := drops("")
		writeJSON(w, buildAlerts(tableLoaded(), abuseSources(), d.Timeline))
	})
	api("/api/abuse-load", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, abuseLoadStatus())
	})
	api("/api/abuseipdb-config", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			body, _ := io.ReadAll(r.Body)
			var req struct {
				APIKey string `json:"api_key"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
				return
			}
			if err := setAbuseIPDBKey(req.APIKey); err != nil {
				http.Error(w, `{"error":"cannot write config: `+err.Error()+`"}`, http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]interface{}{"ok": true, "message": "API key saved. Run nftgeo (systemctl start nftgeo or apply via dashboard) to activate."})
			return
		}
		// GET: report current status from status.json + config file
		st := runStatus()
		if st == nil {
			st = map[string]interface{}{}
		}
		// Also check the config file directly for the key presence
		data, _ := os.ReadFile(configFile)
		keyPresent := false
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "ABUSEIPDB_API_KEY=") {
				val := strings.Trim(strings.TrimSpace(trimmed[len("ABUSEIPDB_API_KEY="):]), `"`)
				if val != "" {
					keyPresent = true
				}
				break
			}
		}
		st["api_key_present"] = keyPresent
		writeJSON(w, st)
	})
	api("/api/top-ips", func(w http.ResponseWriter, r *http.Request) {
		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")
		limitStr := r.URL.Query().Get("limit")
		from, _ := strconv.ParseInt(fromStr, 10, 64)
		to, _ := strconv.ParseInt(toStr, 10, 64)
		limit, _ := strconv.Atoi(limitStr)
		if from == 0 {
			from = time.Now().Add(-24 * time.Hour).Unix()
		}
		writeJSON(w, map[string]interface{}{"ips": topIPs(from, to, limit)})
	})
	// SOC overview: per-interface utilization/error series from the in-memory
	// /proc/net/dev ring, plus the conntrack gauge.
	api("/api/ifstats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ifStats())
	})
	// SOC overview: top source IPs with time-bucketed drop counts.
	api("/api/ip-histogram", func(w http.ResponseWriter, r *http.Request) {
		from, _ := strconv.ParseInt(r.URL.Query().Get("from"), 10, 64)
		buckets, _ := strconv.Atoi(r.URL.Query().Get("buckets"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		writeJSON(w, ipHistogram(from, buckets, limit))
	})
	api("/api/objects", func(w http.ResponseWriter, r *http.Request) {
		writeJSONCached(w, r, objects())
	})
	api("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, map[string]interface{}{"interfaces": hostInterfaces()})
	})
	// INGRESS_DEV: which interface(s) the ingress hook attaches to (the hook is
	// per-device; nftgeo emits one base chain per device, all jumping to the
	// shared ingress_rules). Applies to every ingress rule. GET reads it; POST
	// (rw sessions) writes it to /etc/nftgeo/config. Blank = auto-detect the
	// default-route interface.
	api("/api/ingress-dev", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			var req struct {
				Dev string `json:"dev"`
			}
			body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<12))
			if json.Unmarshal(body, &req) != nil {
				http.Error(w, `{"error":"bad json"}`, http.StatusBadRequest)
				return
			}
			// Accept space- or comma-separated (consistent with target/zone/list
			// fields); normalise to a single space-separated list.
			dev := strings.Join(strings.FieldsFunc(req.Dev, func(r rune) bool {
				return r == ',' || r == ' ' || r == '\t' || r == '\n'
			}), " ")
			// Interface names only; reject anything that could break out of the
			// quoted config value.
			for _, tok := range strings.Fields(dev) {
				for _, c := range tok {
					if !(c == '.' || c == '_' || c == '-' || c == '@' || c == ':' ||
						(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
						http.Error(w, `{"error":"invalid interface name"}`, http.StatusBadRequest)
						return
					}
				}
			}
			if err := setConfigValue("INGRESS_DEV", dev); err != nil {
				http.Error(w, `{"error":"cannot write config"}`, http.StatusInternalServerError)
				return
			}
			writeJSON(w, map[string]interface{}{"ok": true, "dev": dev})
			return
		}
		writeJSON(w, map[string]interface{}{"dev": configValue("INGRESS_DEV"), "interfaces": hostInterfaces()})
	})
	// Built-in well-known services for the port/service autocomplete. Sourced
	// from the engine (`--services`) so the list never drifts from what resolves.
	api("/api/services", func(w http.ResponseWriter, r *http.Request) {
		out, _ := run(engine, "--services")
		type svc struct {
			Name  string `json:"name"`
			Ports string `json:"ports"`
		}
		var list []svc
		for _, ln := range strings.Split(out, "\n") {
			if f := strings.Fields(ln); len(f) == 2 {
				list = append(list, svc{f[0], f[1]})
			}
		}
		writeJSON(w, map[string]interface{}{"services": list})
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
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		writeJSON(w, dropsPage(since, offset, limit))
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
	api("/api/rules/draft/move", handleRulesMove)
	api("/api/rules/draft/toggle", handleRulesToggle)
	api("/api/rules/draft/toggle-log", handleRulesToggleLog)
	api("/api/rules/file/create", handleRulesFileCreate)
	api("/api/rules/draft/save", handleRulesSave)
	api("/api/rules/draft/delete", handleRulesDelete)
	api("/api/rules/draft/section", handleRulesSection)
	api("/api/rules/draft/import", handleRulesImport)
	api("/api/templates", handleTemplates)
	api("/api/templates/delete", handleTemplateDelete)
	api("/api/rule-stats", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, ruleStats())
	})
	api("/api/whitelist/draft", handleWhitelistDraft)
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
