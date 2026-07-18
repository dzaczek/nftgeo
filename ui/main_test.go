package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestSessionCookieSecurity(t *testing.T) {
	tests := []struct {
		name      string
		tls       bool
		forwarded string
		want      bool
	}{
		{name: "local HTTP", want: false},
		{name: "direct HTTPS", tls: true, want: true},
		{name: "TLS reverse proxy", forwarded: "https", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/session", nil)
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}
			r.Header.Set("X-Forwarded-Proto", tt.forwarded)
			cookie := sessionCookie(r, "session-id")
			if cookie.Secure != tt.want {
				t.Errorf("Secure = %t, want %t", cookie.Secure, tt.want)
			}
			if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
				t.Errorf("cookie protections changed: %+v", cookie)
			}
		})
	}
}

func TestSessionAuthFlow(t *testing.T) {
	oldSecret, oldAuthOn, oldTTL := authSecret, authOn, sessionTTL
	authSecret = []byte("0123456789abcdef0123456789abcdef")
	authOn = true
	sessionTTL = time.Hour
	sessMu.Lock()
	oldSessions, oldNonces, oldPending := sessions, usedNonce, pendingSession
	sessions = map[string]*uiSession{}
	usedNonce = map[string]time.Time{}
	pendingSession = nil
	sessMu.Unlock()
	defer func() {
		authSecret, authOn, sessionTTL = oldSecret, oldAuthOn, oldTTL
		sessMu.Lock()
		sessions, usedNonce, pendingSession = oldSessions, oldNonces, oldPending
		sessMu.Unlock()
	}()

	postSession := func(token string) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/session", strings.NewReader(`{"auth":"`+token+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-Proto", "https")
		w := httptest.NewRecorder()
		handleSession(w, r)
		return w
	}

	roToken := mintToken(authSecret, "ro", time.Now().Add(time.Minute))
	roResponse := postSession(roToken)
	if roResponse.Code != http.StatusOK {
		t.Fatalf("read-only token exchange status = %d, body=%s", roResponse.Code, roResponse.Body.String())
	}
	cookies := roResponse.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatalf("unexpected session cookie: %+v", cookies)
	}

	protected := requireAuth(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	readRequest := httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8787/api/status", nil)
	readRequest.AddCookie(cookies[0])
	readResponse := httptest.NewRecorder()
	protected(readResponse, readRequest)
	if readResponse.Code != http.StatusNoContent || readResponse.Header().Get("X-Nftgeo-Mode") != "ro" {
		t.Errorf("read-only GET status/mode = %d/%q, want 204/ro", readResponse.Code, readResponse.Header().Get("X-Nftgeo-Mode"))
	}

	writeRequest := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787/api/rules", nil)
	writeRequest.AddCookie(cookies[0])
	writeResponse := httptest.NewRecorder()
	protected(writeResponse, writeRequest)
	if writeResponse.Code != http.StatusForbidden {
		t.Errorf("read-only POST status = %d, want %d", writeResponse.Code, http.StatusForbidden)
	}

	rwToken := mintToken(authSecret, "rw", time.Now().Add(time.Minute))
	if response := postSession(rwToken); response.Code != http.StatusOK {
		t.Fatalf("read-write token exchange status = %d, body=%s", response.Code, response.Body.String())
	}
	if response := postSession(rwToken); response.Code != http.StatusUnauthorized {
		t.Errorf("reused read-write token status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

// backupLive must create the backup's parent dir (the per-file ui-backups/<...>
// path); a regression here broke every panel deploy from 1.26.0.
func TestBackupLiveCreatesDir(t *testing.T) {
	dir := t.TempDir()
	live := filepath.Join(dir, "live.conf")
	if err := os.WriteFile(live, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	s := stage{live: live, backup: filepath.Join(dir, "ui-backups", "rules.d", "x.conf")}
	if err := backupLive(s); err != nil {
		t.Fatalf("backupLive failed: %v", err)
	}
	if b, err := os.ReadFile(s.backup); err != nil || string(b) != "hello" {
		t.Errorf("backup not written: err=%v content=%q", err, b)
	}
}

func TestBuildRuleBody(t *testing.T) {
	cases := []struct {
		name, action, dir, proto, port, target, iface string
		want                                          string
		wantErr                                       bool
	}{
		{"basic", "allow", "in", "tcp", "22", "any", "", "allow in tcp 22 any", false},
		{"iface", "deny", "out", "udp", "53", "europe", "eth0", "deny out udp 53 europe on eth0", false},
		{"any_portless", "deny", "in", "any", "", "abuse", "", "deny in any - abuse", false},
		{"service_name", "allow", "in", "tcp", "web", "any", "", "allow in tcp web any", false},
		{"list_port", "allow", "in", "tcp", "80,443", "any", "", "allow in tcp 80,443 any", false},
		{"proto_tag", "allow", "in", "any", "dns", "any", "", "allow in any dns any", false},
		{"bad_action", "bogus", "in", "tcp", "22", "any", "", "", true},
		{"bad_dir", "allow", "sideways", "tcp", "22", "any", "", "", true},
		{"bad_proto", "allow", "in", "ftp", "22", "any", "", "", true},
		{"tcp_allports", "allow", "in", "tcp", "", "any", "", "allow in tcp - any", false}, // empty port = every TCP port
		{"inject_target", "allow", "in", "tcp", "22", "any; rm -rf /", "", "", true},
		{"inject_port", "allow", "in", "tcp", "22;rm", "any", "", "", true},
		{"inject_iface", "allow", "in", "tcp", "22", "any", "eth0;x", "", true},
	}
	for _, c := range cases {
		got, err := buildRuleBody(c.action, c.dir, c.proto, c.port, c.target, c.iface)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got %q", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDropReasonRegex(t *testing.T) {
	cases := map[string]struct{ hook, reason string }{
		"nftgeo-drop@input:abuse IN=eth0 SRC=1.2.3.4 DPT=22":   {"input", "abuse"},
		"nftgeo-drop@forward:block others IN=eth0 SRC=1.2.3.4": {"forward", "block others"},
		"nftgeo-drop@input:default-deny IN=eth0 SRC=9.9.9.9":   {"input", "default-deny"},
		"nftgeo-drop:geo IN=eth0 SRC=1.2.3.4":                  {"", "geo"}, // pre-hook prefix remains readable
		"nftgeo-drop IN=eth0 SRC=1.2.3.4":                      {"", ""},    // old prefix, no reason
		"nftgeo-accept@output:allow-ssh IN=eth0 SRC=1.2.3.4":   {"output", "allow-ssh"},
	}
	for msg, want := range cases {
		gotHook, gotReason := "", ""
		if m := reLogPrefix.FindStringSubmatch(msg); m != nil {
			gotHook, gotReason = m[2], m[3]
		}
		if gotHook != want.hook || gotReason != want.reason {
			t.Errorf("%q: got hook=%q reason=%q, want hook=%q reason=%q", msg, gotHook, gotReason, want.hook, want.reason)
		}
	}
}

func TestBuildThrottleBody(t *testing.T) {
	cases := []struct {
		name, dir, proto, port, rate, ban, iface string
		want                                     string
		wantErr                                  bool
	}{
		{"basic", "in", "tcp", "22", "5/minute", "", "", "throttle in tcp 22 5/minute", false},
		{"ban_iface", "fwd-in", "udp", "5060", "20/second", "2h", "eth0", "throttle fwd-in udp 5060 20/second ban 2h on eth0", false},
		{"list_port", "in", "tcp", "22,3389", "3/minute", "", "", "throttle in tcp 22,3389 3/minute", false},
		{"bad_dir", "out", "tcp", "22", "5/minute", "", "", "", true},
		{"bad_proto", "in", "icmp", "22", "5/minute", "", "", "", true},
		{"bad_rate", "in", "tcp", "22", "5/min", "", "", "", true},
		{"bad_ban", "in", "tcp", "22", "5/minute", "soon", "", "", true},
		{"service_port", "in", "tcp", "web", "5/minute", "", "", "", true},
	}
	for _, c := range cases {
		got, err := buildThrottleBody(c.dir, c.proto, c.port, c.rate, c.ban, c.iface)
		if c.wantErr {
			if err == nil {
				t.Errorf("%s: expected error, got %q", c.name, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: unexpected error: %v", c.name, err)
		} else if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestParseThrottleRule(t *testing.T) {
	items, _ := parseDraftRules("throttle in tcp 22 5/minute ban 2h on eth0\n")
	if len(items) != 1 {
		t.Fatalf("got %d items", len(items))
	}
	r := items[0]
	if r.Action != "throttle" || r.Dir != "in" || r.Proto != "tcp" || r.Port != "22" ||
		r.Rate != "5/minute" || r.Ban != "2h" || r.Iface != "eth0" {
		t.Errorf("throttle parsed wrong: %+v", r)
	}
}

func TestParseDraftRulesRoundTrip(t *testing.T) {
	in := "# header\nallow in tcp 22 any # ssh\n## Section\n# deny in tcp 23 any # disabled\ndeny out any - abuse\n"
	items, tail := parseDraftRules(in)
	if got := serializeDraftRules(items, tail); got != in {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", got, in)
	}
}

func TestParseDraftRulesFields(t *testing.T) {
	items, _ := parseDraftRules("allow in tcp 22 any # ssh\n## Web\n# deny in udp 53 any\nallow out tcp 443 europe on eth0\n")
	if len(items) != 4 {
		t.Fatalf("got %d items, want 4", len(items))
	}
	r := items[0]
	if r.Kind != "filter" || r.Action != "allow" || r.Dir != "in" || r.Port != "22" || r.Name != "ssh" {
		t.Errorf("rule0 parsed wrong: %+v", r)
	}
	if items[1].Kind != "section" || items[1].Title != "Web" {
		t.Errorf("item1 not section: %+v", items[1])
	}
	if !items[2].Disabled || items[2].Proto != "udp" {
		t.Errorf("item2 should be a disabled udp rule: %+v", items[2])
	}
	if items[3].Iface != "eth0" {
		t.Errorf("item3 iface: %+v", items[3])
	}
}

func TestParseDraftRulesLog(t *testing.T) {
	// per-rule logging: the "log" token sets Log, is preserved verbatim on
	// round-trip, and does not disturb target/iface parsing.
	in := "allow in tcp 22 pl log # ssh\nallow in tcp 443 any on eth0 log\ndeny in tcp 80 any\n"
	items, tail := parseDraftRules(in)
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3", len(items))
	}
	if !items[0].Log || items[0].Target != "pl" || items[0].Name != "ssh" {
		t.Errorf("rule0: %+v", items[0])
	}
	if !items[1].Log || items[1].Iface != "eth0" || items[1].Target != "any" {
		t.Errorf("rule1: %+v", items[1])
	}
	if items[2].Log {
		t.Errorf("rule2 should not log: %+v", items[2])
	}
	if got := serializeDraftRules(items, tail); got != in {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", got, in)
	}
}

func TestBuildZoneBody(t *testing.T) {
	cases := []struct {
		a, s, d, p, port, geo, want string
		ok                          bool
	}{
		{"allow", "lan", "dmz", "tcp", "80", "", "allow lan -> dmz tcp 80", true},
		{"deny", "dmz", "lan", "any", "", "", "deny dmz -> lan any -", true},
		{"allow", "wan", "dmz", "tcp", "443", "europe", "allow wan -> dmz tcp 443 from europe", true},
		{"allow", "any", "dmz", "tcp", "80", "", "allow any -> dmz tcp 80", true},
		{"drop", "lan", "dmz", "tcp", "80", "", "", false},     // bad action
		{"allow", "l an", "dmz", "tcp", "80", "", "", false},   // bad zone name
		{"allow", "lan", "dmz", "tcp", "", "", "", false},      // tcp needs a port
		{"allow", "lan", "dmz", "tcp", "80", "a b", "", false}, // bad geo
	}
	for _, c := range cases {
		got, err := buildZoneBody(c.a, c.s, c.d, c.p, c.port, c.geo)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("buildZoneBody(%q..)=%q,%v want %q", c.a, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("buildZoneBody(%q..) expected error, got %q", c.a, got)
		}
	}
}

func TestBuildNatBody(t *testing.T) {
	cases := []struct {
		nt, proto, port, target, geo, iface, lan, want string
		ok                                             bool
	}{
		{"masquerade", "", "", "", "", "eth0", "", "masquerade on eth0", true},
		{"masquerade", "", "", "", "", "eth0", "eth1", "masquerade on eth0 in eth1", true},
		{"snat", "", "", "203.0.113.7", "", "eth0", "", "snat out on eth0 to 203.0.113.7", true},
		{"snat", "", "", "203.0.113.7", "", "eth0", "eth1", "snat out on eth0 to 203.0.113.7 in eth1", true},
		{"dnat", "tcp", "8080", "10.0.0.5:80", "", "eth0", "", "dnat tcp 8080 to 10.0.0.5:80 on eth0", true},
		{"dnat", "tcp", "2222", "10.0.0.5:22", "europe", "", "", "dnat tcp 2222 to 10.0.0.5:22 from europe", true},
		{"dnat", "tcp", "443", "[2001:db8::1]:8443", "", "", "", "dnat tcp 443 to [2001:db8::1]:8443", true},
		{"masquerade", "", "", "", "", "", "", "", false},           // needs iface
		{"snat", "", "", "not-an-ip!", "", "eth0", "", "", false},   // bad target
		{"masquerade", "", "", "", "", "eth0", "e th1", "", false},  // bad lan iface
		{"dnat", "icmp", "8080", "10.0.0.5", "", "", "", "", false}, // bad proto
		{"dnat", "tcp", "80x", "10.0.0.5", "", "", "", "", false},   // bad port
		{"bogus", "", "", "", "", "eth0", "", "", false},            // bad type
	}
	for _, c := range cases {
		got, err := buildNatBody(c.nt, c.proto, c.port, c.target, c.geo, c.iface, c.lan)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("buildNatBody(%q..)=%q,%v want %q", c.nt, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("buildNatBody(%q..) expected error, got %q", c.nt, got)
		}
	}
}

func TestFilterNewDropsDedup(t *testing.T) {
	rfc := func(sec int64) string { return time.Unix(sec, 0).UTC().Format(time.RFC3339) }
	now := int64(3000)
	recent := []Drop{
		{Time: rfc(1000), Src: "1.1.1.1"},
		{Time: rfc(1500), Src: "2.2.2.2"},
	}
	// first ingest (hw starts at 0): both are new; high-water-mark = 1500
	e1, hw1 := filterNewDrops(recent, 0, now)
	if len(e1) != 2 || hw1 != 1500 {
		t.Fatalf("first ingest: %d entries, hw %d (want 2, 1500)", len(e1), hw1)
	}
	// re-poll the SAME window (the old bug ingested these ~12x): nothing new
	e2, hw2 := filterNewDrops(recent, hw1, now)
	if len(e2) != 0 || hw2 != 1500 {
		t.Fatalf("re-ingest double-counted: %d entries, hw %d (want 0, 1500)", len(e2), hw2)
	}
	// a genuinely newer drop appears: only it is ingested
	recent3 := append(recent, Drop{Time: rfc(1800), Src: "3.3.3.3"})
	e3, hw3 := filterNewDrops(recent3, hw2, now)
	if len(e3) != 1 || e3[0].Src != "3.3.3.3" || hw3 != 1800 {
		t.Fatalf("new drop: %+v, hw %d (want 1x 3.3.3.3, 1800)", e3, hw3)
	}
}

func TestStatsTimeline(t *testing.T) {
	now := time.Unix(100000, 0)
	statsMu.Lock()
	saved := statsData
	statsData = []statsEntry{
		{Ts: now.Unix() - 30},          // 0h ago -> newest bucket [23]
		{Ts: now.Unix() - 3*3600 - 10}, // 3h ago -> bucket [20]
		{Ts: now.Unix() - 3*3600 - 20}, // 3h ago -> bucket [20]
		{Ts: now.Unix() - 25*3600},     // older than 24h -> dropped
		{Ts: now.Unix() + 60},          // future clock skew -> dropped
	}
	statsMu.Unlock()
	defer func() { statsMu.Lock(); statsData = saved; statsMu.Unlock() }()

	tl := statsTimeline(now)
	if len(tl) != 24 || tl[23] != 1 || tl[20] != 2 {
		t.Fatalf("timeline = %v (want 24 buckets, [23]=1, [20]=2)", tl)
	}
	sum := 0
	for _, v := range tl {
		sum += v
	}
	if sum != 3 {
		t.Fatalf("timeline sum = %d (want 3: out-of-window entries must be excluded)", sum)
	}
}

func TestBackfillFromStats(t *testing.T) {
	now := time.Unix(100000, 0)
	statsMu.Lock()
	saved := statsData
	// Appended in ingest (time-ascending) order, as the real store is.
	statsData = []statsEntry{
		{Ts: now.Unix() - 25*3600, Src: "9.9.9.9", CC: "FR", Port: "80"}, // out of 24h window
		{Ts: now.Unix() - 3600, Src: "1.1.1.1", Dst: "10.0.0.1", CC: "US", Port: "22", Proto: "TCP", Hook: "input", Dir: "ingress", Reason: "abuse"},
		{Ts: now.Unix() - 60, Src: "2.2.2.2", Dst: "10.0.0.2", CC: "DE", Port: "22", Proto: "TCP", Hook: "input", Dir: "ingress", Reason: "geo"}, // newest
	}
	statsMu.Unlock()
	defer func() { statsMu.Lock(); statsData = saved; statsMu.Unlock() }()

	// Empty live feed -> everything is reconstructed from the store.
	empty := DropsResp{IngressByCC: map[string]int{}, EgressByCC: map[string]int{}, TopPorts: map[string]int{}, Timeline: make([]int, 24)}
	backfillFromStats(&empty, now)
	// Total / breakdowns are 24h-windowed (FR/80 excluded); Recent is not.
	if empty.Total != 2 {
		t.Errorf("Total = %d, want 2 (out-of-window excluded)", empty.Total)
	}
	if empty.TopPorts["22"] != 2 || empty.TopPorts["80"] != 0 {
		t.Errorf("TopPorts = %v, want 22=2 80=0", empty.TopPorts)
	}
	if empty.IngressByCC["US"] != 1 || empty.IngressByCC["DE"] != 1 || empty.IngressByCC["FR"] != 0 {
		t.Errorf("IngressByCC = %v, want US=1 DE=1 FR=0", empty.IngressByCC)
	}
	if len(empty.Recent) != 3 || empty.Recent[0].Src != "2.2.2.2" {
		t.Errorf("Recent = %+v, want 3 rows newest-first (2.2.2.2 first)", empty.Recent)
	}
	if got := empty.Recent[0]; got.Dst != "10.0.0.2" || got.Proto != "TCP" || got.Hook != "input" || got.Dir != "incoming" {
		t.Errorf("Recent details = %+v, want persisted destination/proto/hook/flow", got)
	}

	// Live feed present -> breakdowns/recent must NOT be overwritten.
	live := DropsResp{
		IngressByCC: map[string]int{"PL": 5},
		EgressByCC:  map[string]int{},
		TopPorts:    map[string]int{"443": 9},
		Timeline:    make([]int, 24),
		Recent:      []Drop{{Src: "8.8.8.8", Verdict: "drop"}},
	}
	backfillFromStats(&live, now)
	if live.IngressByCC["PL"] != 5 || live.IngressByCC["US"] != 0 {
		t.Errorf("live IngressByCC overwritten: %v", live.IngressByCC)
	}
	if live.TopPorts["443"] != 9 || live.TopPorts["22"] != 0 {
		t.Errorf("live TopPorts overwritten: %v", live.TopPorts)
	}
	if len(live.Recent) != 1 || live.Recent[0].Src != "8.8.8.8" {
		t.Errorf("live Recent overwritten: %+v", live.Recent)
	}
}

func TestPageRecent(t *testing.T) {
	resp := DropsResp{Recent: []Drop{{Src: "1"}, {Src: "2"}, {Src: "3"}}}
	pageRecent(&resp, 1, 1)
	if resp.RecentTotal != 3 || !resp.HasMore || len(resp.Recent) != 1 || resp.Recent[0].Src != "2" {
		t.Errorf("page = %+v, want second of three with more pages", resp)
	}

	resp = DropsResp{Recent: []Drop{{Src: "1"}, {Src: "2"}, {Src: "3"}}}
	pageRecent(&resp, 3, 1)
	if resp.HasMore || len(resp.Recent) != 0 {
		t.Errorf("past-end page = %+v, want empty final page", resp)
	}
}

func TestBuildSynproxyBody(t *testing.T) {
	cases := []struct {
		dir, port, iface, want string
		ok                     bool
	}{
		{"in", "22", "", "synproxy in tcp 22", true},
		{"fwd-in", "80,443", "eth0", "synproxy fwd-in tcp 80,443 on eth0", true},
		{"out", "22", "", "", false},     // bad dir
		{"in", "22x", "", "", false},     // bad port
		{"in", "22", "e th0", "", false}, // bad iface
	}
	for _, c := range cases {
		got, err := buildSynproxyBody(c.dir, c.port, c.iface)
		if c.ok && (err != nil || got != c.want) {
			t.Errorf("buildSynproxyBody(%q,%q,%q)=%q,%v want %q", c.dir, c.port, c.iface, got, err, c.want)
		}
		if !c.ok && err == nil {
			t.Errorf("buildSynproxyBody(%q,%q,%q) expected error, got %q", c.dir, c.port, c.iface, got)
		}
	}
}

func TestParseSynproxyRule(t *testing.T) {
	items, _ := parseDraftRules("synproxy in tcp 22\nsynproxy fwd-in tcp 80,443 on eth0 # web\n")
	if len(items) != 2 {
		t.Fatalf("got %d items, want 2", len(items))
	}
	if items[0].Kind != "synproxy" || items[0].Dir != "in" || items[0].Proto != "tcp" || items[0].Port != "22" || items[0].Iface != "" {
		t.Errorf("synproxy0 parsed wrong: %+v", items[0])
	}
	if items[1].Kind != "synproxy" || items[1].Dir != "fwd-in" || items[1].Port != "80,443" || items[1].Iface != "eth0" || items[1].Name != "web" {
		t.Errorf("synproxy1 parsed wrong: %+v", items[1])
	}
}

func TestParseDraftRulesNatZone(t *testing.T) {
	in := "masquerade on eth0\n" +
		"snat out on eth0 to 203.0.113.7\n" +
		"dnat tcp 8080 to 10.0.0.5:80 on eth0\n" +
		"allow lan -> dmz tcp 80\n" +
		"deny dmz -> lan any - # lockdown\n" +
		"allow wan -> dmz tcp 443 from europe\n"
	items, tail := parseDraftRules(in)
	if len(items) != 6 {
		t.Fatalf("got %d items, want 6", len(items))
	}
	// NAT rows: kind=nat, verbatim Text, iface surfaced, never a filter row.
	for i := 0; i < 3; i++ {
		if items[i].Kind != "nat" {
			t.Errorf("item%d kind=%q, want nat: %+v", i, items[i].Kind, items[i])
		}
		// Action/Dir must stay empty so a nat row is never treated as a filter row
		// (Target/Proto/Port are legitimately reused for nat edit-drawer prefill).
		if items[i].Action != "" || items[i].Dir != "" {
			t.Errorf("item%d leaked filter fields: %+v", i, items[i])
		}
	}
	if items[0].Text != "masquerade on eth0" || items[0].Iface != "eth0" || items[0].NatType != "masquerade" {
		t.Errorf("masquerade parsed wrong: %+v", items[0])
	}
	if items[1].NatType != "snat" || items[1].Target != "203.0.113.7" || items[1].Iface != "eth0" {
		t.Errorf("snat prefill fields wrong: %+v", items[1])
	}
	if items[2].NatType != "dnat" || items[2].Proto != "tcp" || items[2].Port != "8080" || items[2].Target != "10.0.0.5:80" || items[2].Iface != "eth0" {
		t.Errorf("dnat prefill fields wrong: %+v", items[2])
	}
	// Zone rows: kind=zone, src/dst/proto/port, and Proto must not be "->".
	z := items[3]
	if z.Kind != "zone" || z.Action != "allow" || z.Src != "lan" || z.Dst != "dmz" || z.Proto != "tcp" || z.Port != "80" {
		t.Errorf("zone rule parsed wrong: %+v", z)
	}
	if items[4].Kind != "zone" || !(items[4].Action == "deny") || items[4].Name != "lockdown" {
		t.Errorf("zone deny parsed wrong: %+v", items[4])
	}
	if items[5].Geo != "europe" {
		t.Errorf("zone from-geo not captured: %+v", items[5])
	}
	// Round-trip must be byte-identical (verbatim Body + name preserved).
	if got := serializeDraftRules(items, tail); got != in {
		t.Errorf("round-trip mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, in)
	}
}

func TestObjectsRoundTrip(t *testing.T) {
	g, r, s, h, z, l, f := parseObjects(`GROUP_OFFICE="10.0.0.0/24 1.2.3.4"` + "\n" + `REGION_BLK="ru cn"` + "\n" + `SERVICE_WEB="80 443/tcp"` + "\n" + `HOST_DB1="10.0.0.5"` + "\n" + `ZONE_GUEST="eth1 eth0.100"` + "\n" + `LIST_BADGUYS="1.2.3.4 5.6.7.0/24"` + "\n" + `FEED_SPAMHAUS="https://www.spamhaus.org/drop/drop.txt"` + "\n")
	if len(g) != 1 || len(r) != 1 || len(s) != 1 || len(h) != 1 || len(z) != 1 || len(l) != 1 || len(f) != 1 {
		t.Fatalf("counts g=%d r=%d s=%d h=%d z=%d l=%d f=%d", len(g), len(r), len(s), len(h), len(z), len(l), len(f))
	}
	if f[0].Name != "SPAMHAUS" || f[0].Members[0] != "https://www.spamhaus.org/drop/drop.txt" {
		t.Errorf("feed parsed wrong: %+v", f)
	}
	if g[0].Name != "OFFICE" || len(g[0].Members) != 2 || g[0].Members[1] != "1.2.3.4" {
		t.Errorf("group parsed wrong: %+v", g[0])
	}
	if s[0].Name != "WEB" || s[0].Members[1] != "443/tcp" {
		t.Errorf("service parsed wrong: %+v", s[0])
	}
	if h[0].Name != "DB1" || h[0].Members[0] != "10.0.0.5" {
		t.Errorf("host parsed wrong: %+v", h[0])
	}
	if z[0].Name != "GUEST" || len(z[0].Members) != 2 || z[0].Members[1] != "eth0.100" {
		t.Errorf("zone parsed wrong: %+v", z[0])
	}
	out := serializeObjects(g, r, s, h, z, l, f)
	if !strings.Contains(out, `FEED_SPAMHAUS=`) || !strings.Contains(out, `ABUSE_FEEDS_UI=`) {
		t.Errorf("serialize should emit FEED_* and the derived ABUSE_FEEDS_UI: %q", out)
	}
	g2, r2, s2, h2, z2, l2, f2 := parseObjects(out)
	if len(g2) != 1 || len(r2) != 1 || len(s2) != 1 || len(h2) != 1 || len(z2) != 1 || len(l2) != 1 || len(f2) != 1 {
		t.Errorf("re-parse of serialized objects lost entries: %q", out)
	}
}

func TestSanitizeObjectsFeedURLs(t *testing.T) {
	ok := []objEntry{{Name: "FIREHOL", Members: []string{"https://iplists.firehol.org/files/firehol_level1.netset"}}}
	if err := sanitizeObjects(nil, nil, nil, nil, nil, nil, ok); err != nil {
		t.Errorf("valid feed rejected: %v", err)
	}
	for _, bad := range []string{
		"ftp://x/list",             // not http(s)
		`https://x/$(reboot)`,      // shell $()
		"https://x/a b",            // whitespace
		"https://x/\"; rm -rf /\"", // quote/inject
		"https://x/`id`",           // backtick
	} {
		if err := sanitizeObjects(nil, nil, nil, nil, nil, nil, []objEntry{{Name: "X", Members: []string{bad}}}); err == nil {
			t.Errorf("expected feed URL %q to be rejected", bad)
		}
	}
	// bad label / empty url
	if err := sanitizeObjects(nil, nil, nil, nil, nil, nil, []objEntry{{Name: "bad label", Members: []string{"https://x/y"}}}); err == nil {
		t.Error("expected bad feed label to be rejected")
	}
	if err := sanitizeObjects(nil, nil, nil, nil, nil, nil, []objEntry{{Name: "X", Members: nil}}); err == nil {
		t.Error("expected feed with no URL to be rejected")
	}
}

func TestSanitizeObjectsRejectsInjection(t *testing.T) {
	if err := sanitizeObjects([]objEntry{{Name: "X", Members: []string{"1.2.3.4; rm"}}}, nil, nil, nil, nil, nil, nil); err == nil {
		t.Error("expected shell-metachar member to be rejected")
	}
	if err := sanitizeObjects([]objEntry{{Name: "bad name", Members: nil}}, nil, nil, nil, nil, nil, nil); err == nil {
		t.Error("expected invalid name to be rejected")
	}
	if err := sanitizeObjects([]objEntry{{Name: "OK", Members: []string{"80", "443/tcp"}}}, nil, nil, nil, nil, nil, nil); err != nil {
		t.Errorf("valid service members rejected: %v", err)
	}
	// zone interface members: VLAN subif OK, shell metachars rejected
	if err := sanitizeObjects(nil, nil, nil, nil, []objEntry{{Name: "GUEST", Members: []string{"eth0.100", "br-lan"}}}, nil, nil); err != nil {
		t.Errorf("valid zone interfaces rejected: %v", err)
	}
	if err := sanitizeObjects(nil, nil, nil, nil, []objEntry{{Name: "Z", Members: []string{"eth0; rm"}}}, nil, nil); err == nil {
		t.Error("expected bad zone interface to be rejected")
	}
}

func TestSanitizeComment(t *testing.T) {
	if got := sanitizeComment("a # b\nc"); got == "" || got == "a # b\nc" {
		t.Errorf("sanitizeComment did not strip # / newline: %q", got)
	}
}

func TestRuleComment(t *testing.T) {
	cases := []struct {
		action, dir, proto, port, target, iface, want string
	}{
		{"allow", "in", "tcp", "22", "any", "", "nftgeo:allow in tcp 22 any"},
		{"allow", "in", "tcp", "HERMES", "VPN", "wg0", "nftgeo:allow in tcp HERMES VPN on wg0"},
		{"deny", "in", "any", "-", "abuse", "-", "nftgeo:deny in any - abuse"},
	}
	for _, c := range cases {
		if got := ruleComment(c.action, c.dir, c.proto, c.port, c.target, c.iface); got != c.want {
			t.Errorf("got %q, want %q", got, c.want)
		}
	}
}

func TestDetectSpike(t *testing.T) {
	cases := []struct {
		name     string
		timeline []int
		want     bool
	}{
		{"flat-no-spike", []int{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10}, false},
		{"spike-3x-over-floor", []int{50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 50, 600, 0}, true},
		{"all-zeros", []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, false},
		{"below-floor", []int{10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 100, 0}, false},
		{"spike-no-baseline-5x", []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1100, 0}, true},
		{"no-spike-no-baseline-below-5x", []int{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 500, 0}, false},
		{"too-short", []int{1, 2, 3}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, _, _ := detectSpike(c.timeline)
			if got != c.want {
				t.Errorf("detectSpike() = %v, want %v", got, c.want)
			}
		})
	}
}

func TestBuildAlerts(t *testing.T) {
	// not-loaded
	alerts := buildAlerts(false, nil, nil)
	if len(alerts) != 1 || alerts[0].Kind != "not-loaded" {
		t.Fatalf("expected 1 not-loaded alert, got %+v", alerts)
	}

	// healthy — no alerts
	healthyFeeds := []map[string]interface{}{
		{"name": "AbuseIPDB", "fresh": true, "ageHours": 2},
	}
	flatTimeline := make([]int, 24)
	alerts = buildAlerts(true, healthyFeeds, flatTimeline)
	if len(alerts) != 0 {
		t.Fatalf("expected 0 alerts for healthy state, got %+v", alerts)
	}

	// feed-stale
	staleFeeds := []map[string]interface{}{
		{"name": "EvilFeed", "fresh": false, "ageHours": 48},
	}
	alerts = buildAlerts(true, staleFeeds, flatTimeline)
	if len(alerts) != 1 || alerts[0].Kind != "feed-stale" {
		t.Fatalf("expected 1 feed-stale alert, got %+v", alerts)
	}

	// drop-spike
	spikeTimeline := make([]int, 24)
	for i := range spikeTimeline[:22] {
		spikeTimeline[i] = 100
	}
	spikeTimeline[22] = 600 // 6x baseline, above floor
	alerts = buildAlerts(true, healthyFeeds, spikeTimeline)
	if len(alerts) != 1 || alerts[0].Kind != "drop-spike" {
		t.Fatalf("expected 1 drop-spike alert, got %+v", alerts)
	}
}

// rdapCIDR must handle IPv6 blocks (v6prefix), not just IPv4 (v4prefix); the
// v4-only version rendered "<nil>/29" for every IPv6 drop lookup.
func TestRDAPCIDRFamilies(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]interface{}
		want string
	}{
		{"ipv4", map[string]interface{}{"v4prefix": "1.2.3.0", "length": float64(24)}, "1.2.3.0/24"},
		{"ipv6", map[string]interface{}{"v6prefix": "2606:4700::", "length": float64(32)}, "2606:4700::/32"},
		{"neither", map[string]interface{}{"length": float64(29)}, ""},
	}
	for _, c := range cases {
		if got := rdapCIDR(c.in); got != c.want {
			t.Errorf("%s: rdapCIDR = %q, want %q", c.name, got, c.want)
		}
	}
}

// A feed URL on a "blocklist.*" host must not be mislabeled "blocklist"; the
// provider name (or the operator's FEED_ label) should win.
func TestShortFeedNaming(t *testing.T) {
	cases := map[string]string{
		"https___blocklist_greensnow_co_greensnow_txt":                             "greensnow",
		"https___iplists_firehol_org_files_firehol_level1_netset":                  "firehol",
		"https___www_spamhaus_org_drop_drop_txt":                                   "spamhaus",
		"https___raw_githubusercontent_com_borestad_blocklist_abuseipdb_main_ipv4": "abuseipdb",
		"https___lists_blocklist_de_lists_all_txt":                                 "blocklist.de",
	}
	for in, want := range cases {
		if got := shortFeed(in); got != want {
			t.Errorf("shortFeed(%q) = %q, want %q", in, got, want)
		}
	}
	if got := sanitizeFeedURL("https://blocklist.greensnow.co/greensnow.txt"); got != "https___blocklist_greensnow_co_greensnow_txt" {
		t.Errorf("sanitizeFeedURL mismatch: %q", got)
	}
}

func TestValidWhitelistEntry(t *testing.T) {
	for _, s := range []string{"203.0.113.5", "10.0.0.0/8", "2001:db8::1", "2001:db8::/48"} {
		if !validWhitelistEntry(s) {
			t.Errorf("validWhitelistEntry(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "not-an-ip", "999.1.1.1", "10.0.0.0/33", "example.com"} {
		if validWhitelistEntry(s) {
			t.Errorf("validWhitelistEntry(%q) = true, want false", s)
		}
	}
	for _, s := range []string{"vpn.example.ch", "host-1.internal_net"} {
		if !validHostname(s) {
			t.Errorf("validHostname(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"", "bad host", "a;b", "x`y"} {
		if validHostname(s) {
			t.Errorf("validHostname(%q) = true, want false", s)
		}
	}
}

// The dedicated whitelist file is authoritative once it has an entry; an empty
// or absent file falls back to the legacy config variable. This is the core of
// the fix for #37 (an entry removed in the UI must stay removed).
func TestCurrentWhitelistFilePrecedence(t *testing.T) {
	dir := t.TempDir()
	cf := filepath.Join(dir, "config")
	wf := filepath.Join(dir, "whitelist.conf")
	if err := os.WriteFile(cf, []byte("WHITELIST=\"1.1.1.1 2.2.2.2\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	oc, ow := configFile, whitelistFile
	configFile, whitelistFile = cf, wf
	defer func() { configFile, whitelistFile = oc, ow }()

	// No file yet → legacy config var.
	if got := currentWhitelist(); len(got) != 2 {
		t.Fatalf("no file: got %v, want the 2 config entries", got)
	}
	// File with entries → file wins (config var ignored, so a removal sticks).
	if err := os.WriteFile(wf, []byte("# managed\n9.9.9.9\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got := currentWhitelist()
	if len(got) != 1 || got[0] != "9.9.9.9" {
		t.Errorf("with file: got %v, want [9.9.9.9]", got)
	}
	// Empty file → back to the config var (safety fallback, no accidental empty).
	if err := os.WriteFile(wf, []byte("# only a comment\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if got := currentWhitelist(); len(got) != 2 {
		t.Errorf("empty file: got %v, want the 2 config entries", got)
	}
}

func TestParseDraftRulesIngress(t *testing.T) {
	in := "drop abuse # bad\naccept 203.0.113.0/24\ndrop any tcp 22 log\n"
	items, tail := parseDraftRules(in)
	if len(items) != 3 {
		t.Fatalf("got %d items, want 3", len(items))
	}
	if items[0].Kind != "ingress" || items[0].Action != "drop" || items[0].Target != "abuse" || items[0].Name != "bad" {
		t.Errorf("rule0: %+v", items[0])
	}
	if items[2].Proto != "tcp" || items[2].Port != "22" || !items[2].Log {
		t.Errorf("rule2: %+v", items[2])
	}
	if got := serializeDraftRules(items, tail); got != in {
		t.Errorf("round-trip mismatch:\n got %q\nwant %q", got, in)
	}
}

func TestBuildIngressBody(t *testing.T) {
	if b, err := buildIngressBody("drop", "abuse", "", "", false); err != nil || b != "drop abuse" {
		t.Errorf("drop abuse: got %q err %v", b, err)
	}
	if b, err := buildIngressBody("drop", "any", "tcp", "22", true); err != nil || b != "drop any tcp 22 log" {
		t.Errorf("drop any tcp 22 log: got %q err %v", b, err)
	}
	if _, err := buildIngressBody("accept", "abuse", "", "", false); err == nil {
		t.Error("accept abuse should be rejected")
	}
	if _, err := buildIngressBody("bogus", "any", "", "", false); err == nil {
		t.Error("bad action should be rejected")
	}
}

func TestParseObjects(t *testing.T) {
	input := `
# A comment
   # indented comment

GROUP_MYGROUP="1.1.1.1 2.2.2.2"
REGION_MYREGION="us gb"
SERVICE_MYSERVICE="80/tcp 443/tcp"
HOST_MYHOST="10.0.0.1"
ZONE_MYZONE="eth0"
LIST_MYLIST="192.168.1.0/24"
FEED_MYFEED="https://example.com/feed.txt"
ABUSE_FEEDS_UI="https://example.com/feed.txt"
INVALID_LINE
`
	g, r, s, h, z, l, f := parseObjects(input)

	if len(g) != 1 || g[0].Name != "MYGROUP" || len(g[0].Members) != 2 || g[0].Members[0] != "1.1.1.1" || g[0].Members[1] != "2.2.2.2" {
		t.Errorf("failed to parse GROUP: %+v", g)
	}
	if len(r) != 1 || r[0].Name != "MYREGION" || len(r[0].Members) != 2 || r[0].Members[0] != "us" || r[0].Members[1] != "gb" {
		t.Errorf("failed to parse REGION: %+v", r)
	}
	if len(s) != 1 || s[0].Name != "MYSERVICE" || len(s[0].Members) != 2 || s[0].Members[0] != "80/tcp" || s[0].Members[1] != "443/tcp" {
		t.Errorf("failed to parse SERVICE: %+v", s)
	}
	if len(h) != 1 || h[0].Name != "MYHOST" || len(h[0].Members) != 1 || h[0].Members[0] != "10.0.0.1" {
		t.Errorf("failed to parse HOST: %+v", h)
	}
	if len(z) != 1 || z[0].Name != "MYZONE" || len(z[0].Members) != 1 || z[0].Members[0] != "eth0" {
		t.Errorf("failed to parse ZONE: %+v", z)
	}
	if len(l) != 1 || l[0].Name != "MYLIST" || len(l[0].Members) != 1 || l[0].Members[0] != "192.168.1.0/24" {
		t.Errorf("failed to parse LIST: %+v", l)
	}
	if len(f) != 1 || f[0].Name != "MYFEED" || len(f[0].Members) != 1 || f[0].Members[0] != "https://example.com/feed.txt" {
		t.Errorf("failed to parse FEED: %+v", f)
	}
}

func TestParseDur(t *testing.T) {
	def := 15 * time.Minute
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"10m", 10 * time.Minute},
		{"1h", 1 * time.Hour},
		{"", def},
		{"invalid", def},
		{"10", def}, // missing unit
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			if got := parseDur(c.in, def); got != c.want {
				t.Errorf("parseDur(%q, %v) = %v, want %v", c.in, def, got, c.want)
			}
		})
	}
}

func TestParseList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "standard input",
			input: "item1\nitem2\nitem3",
			want:  []string{"item1", "item2", "item3"},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "comments only",
			input: "# comment 1\n# comment 2",
			want:  nil,
		},
		{
			name:  "mixed input",
			input: "item1\n# comment\n  \nitem2  \n\titem3\t\n",
			want:  []string{"item1", "item2", "item3"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseList(tt.input)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseList() got = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---- shared mutation core (TUI + web handlers use one implementation) ----

// ruleTestEnv points every rule/stage path at a temp dir so the shared
// mutation functions can be exercised without touching the system.
func ruleTestEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	saved := []struct {
		p   *string
		val string
	}{
		{&rulesFile, filepath.Join(dir, "rules.conf")},
		{&rulesDir, filepath.Join(dir, "rules.d")},
		{&ingressFile, filepath.Join(dir, "ingress.conf")},
		{&ingressDir, filepath.Join(dir, "ingress.d")},
		{&draftDir, filepath.Join(dir, "drafts")},
		{&backupDir, filepath.Join(dir, "backups")},
		{&objLiveFile, filepath.Join(dir, "objects.conf")},
		{&objDraftFile, filepath.Join(dir, "drafts", "objects")},
		{&objBackupFile, filepath.Join(dir, "backups", "objects")},
		{&wlDraftFile, filepath.Join(dir, "drafts", "whitelist")},
		{&wlHostsDraftFile, filepath.Join(dir, "drafts", "whitelist-hosts")},
		{&whitelistFile, filepath.Join(dir, "whitelist.conf")},
		{&whitelistHostsFile, filepath.Join(dir, "whitelist-hosts.conf")},
		{&wlBackupFile, filepath.Join(dir, "backups", "whitelist")},
		{&wlHostsBackupFile, filepath.Join(dir, "backups", "whitelist-hosts")},
		{&sentinel, filepath.Join(dir, ".pending-confirm")},
	}
	for i := range saved {
		old := *saved[i].p
		p := saved[i].p
		*p = saved[i].val
		t.Cleanup(func() { *p = old })
	}
	os.WriteFile(rulesFile, []byte("# rules\n"), 0644)
	return dir
}

func TestWriteObjectsDraftShared(t *testing.T) {
	ruleTestEnv(t)
	groups := []objEntry{{Name: "WEB", Members: []string{"1.2.3.4"}}}
	changed, errMsg, _ := writeObjectsDraft(groups, nil, nil, nil, nil, nil, nil)
	if errMsg != "" {
		t.Fatalf("valid objects rejected: %s", errMsg)
	}
	if changed == 0 {
		t.Errorf("changed = 0, want >0 (draft differs from empty live)")
	}
	want := serializeObjects(groups, nil, nil, nil, nil, nil, nil)
	if got := readFileStr(objDraftFile); got != want {
		t.Errorf("draft content mismatch:\n got: %q\nwant: %q", got, want)
	}
	// invalid name is rejected with a 400 and no write
	os.Remove(objDraftFile)
	_, errMsg, code := writeObjectsDraft([]objEntry{{Name: "bad name!", Members: []string{"1.1.1.1"}}}, nil, nil, nil, nil, nil, nil)
	if errMsg == "" || code != 400 {
		t.Errorf("invalid object accepted: errMsg=%q code=%d", errMsg, code)
	}
	if _, err := os.Stat(objDraftFile); err == nil {
		t.Errorf("draft written despite validation error")
	}
}

func TestSaveWhitelistDraftShared(t *testing.T) {
	ruleTestEnv(t)
	if errMsg, _ := saveWhitelistDraft([]string{"10.0.0.1", "192.168.0.0/24"}, []string{"host.example.com"}); errMsg != "" {
		t.Fatalf("valid whitelist rejected: %s", errMsg)
	}
	if got := readFileStr(wlDraftFile); got != serializeListFile([]string{"10.0.0.1", "192.168.0.0/24"}) {
		t.Errorf("whitelist draft mismatch: %q", got)
	}
	if got := readFileStr(wlHostsDraftFile); got != serializeListFile([]string{"host.example.com"}) {
		t.Errorf("whitelist-hosts draft mismatch: %q", got)
	}
	if errMsg, code := saveWhitelistDraft([]string{"not an ip"}, nil); errMsg == "" || code != 400 {
		t.Errorf("invalid entry accepted: errMsg=%q code=%d", errMsg, code)
	}
	if errMsg, code := saveWhitelistDraft(nil, []string{"bad host!"}); errMsg == "" || code != 400 {
		t.Errorf("invalid host accepted: errMsg=%q code=%d", errMsg, code)
	}
}

func TestSaveRuleDraftKinds(t *testing.T) {
	ruleTestEnv(t)
	cases := []struct {
		name string
		req  ruleSaveReq
		want func() (string, error)
	}{
		{"filter", ruleSaveReq{File: "rules.conf", Action: "allow", Dir: "in", Proto: "tcp", Port: "22", Target: "any", Name: "ssh"},
			func() (string, error) { return buildRuleBody("allow", "in", "tcp", "22", "any", "") }},
		{"throttle", ruleSaveReq{File: "rules.conf", Action: "throttle", Dir: "in", Proto: "tcp", Port: "22", Rate: "5/minute", Name: "tt"},
			func() (string, error) { return buildThrottleBody("in", "tcp", "22", "5/minute", "", "") }},
		{"synproxy", ruleSaveReq{File: "rules.conf", Kind: "synproxy", Dir: "in", Port: "443", Name: "sp"},
			func() (string, error) { return buildSynproxyBody("in", "443", "") }},
		{"zone", ruleSaveReq{File: "rules.conf", Kind: "zone", Action: "allow", Src: "lan", Dst: "wan", Proto: "tcp", Port: "80", Name: "z"},
			func() (string, error) { return buildZoneBody("allow", "lan", "wan", "tcp", "80", "") }},
		{"ingress", ruleSaveReq{File: "rules.conf", Kind: "ingress", Action: "drop", Target: "abuse", Proto: "tcp", Port: "25", Name: "ig"},
			func() (string, error) { return buildIngressBody("drop", "abuse", "tcp", "25", false) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			os.RemoveAll(draftDir)
			if errMsg, _ := saveRuleDraft(c.req); errMsg != "" {
				t.Fatalf("saveRuleDraft: %s", errMsg)
			}
			wantBody, err := c.want()
			if err != nil {
				t.Fatalf("builder: %v", err)
			}
			rf := findRuleFileByRel("rules.conf")
			rules, _ := parseDraftRules(draftTextFor(*rf))
			if len(rules) != 1 {
				t.Fatalf("rules = %d, want 1", len(rules))
			}
			if rules[0].Body != wantBody {
				t.Errorf("body = %q, want %q (must match the web builder)", rules[0].Body, wantBody)
			}
		})
	}
	// edit in place: append then edit by ID
	os.RemoveAll(draftDir)
	saveRuleDraft(ruleSaveReq{File: "rules.conf", Action: "deny", Dir: "in", Proto: "any", Target: "1.2.3.4", Name: "old"})
	rf := findRuleFileByRel("rules.conf")
	rules, _ := parseDraftRules(draftTextFor(*rf))
	id := rules[0].ID
	if errMsg, _ := saveRuleDraft(ruleSaveReq{File: "rules.conf", ID: &id, Action: "deny", Dir: "in", Proto: "any", Target: "5.6.7.8", Name: "new"}); errMsg != "" {
		t.Fatalf("edit: %s", errMsg)
	}
	rules, _ = parseDraftRules(draftTextFor(*rf))
	if len(rules) != 1 || !strings.Contains(rules[0].Body, "5.6.7.8") || rules[0].Name != "new" {
		t.Errorf("edit did not replace in place: %+v", rules[0])
	}
	// error paths
	if errMsg, code := saveRuleDraft(ruleSaveReq{File: "nope.conf", Action: "deny", Dir: "in", Proto: "any", Target: "1.1.1.1"}); errMsg != "unknown rule file" || code != 400 {
		t.Errorf("unknown file: errMsg=%q code=%d", errMsg, code)
	}
	if errMsg, code := saveRuleDraft(ruleSaveReq{File: "rules.conf", Action: "bogus", Dir: "in", Proto: "tcp", Port: "1", Target: "any"}); errMsg == "" || code != 400 {
		t.Errorf("bad action accepted: errMsg=%q code=%d", errMsg, code)
	}
}

func TestToggleMoveDeleteRuleDraft(t *testing.T) {
	ruleTestEnv(t)
	for _, target := range []string{"1.1.1.1", "2.2.2.2", "3.3.3.3"} {
		saveRuleDraft(ruleSaveReq{File: "rules.conf", Action: "deny", Dir: "in", Proto: "any", Target: target})
	}
	rf := findRuleFileByRel("rules.conf")
	rules, _ := parseDraftRules(draftTextFor(*rf))
	if len(rules) != 3 {
		t.Fatalf("seed: %d rules, want 3", len(rules))
	}
	// toggle
	disabled, errMsg, _ := toggleRuleDraft("rules.conf", rules[1].ID)
	if errMsg != "" || !disabled {
		t.Fatalf("toggle: errMsg=%q disabled=%v", errMsg, disabled)
	}
	rules, _ = parseDraftRules(draftTextFor(*rf))
	if !rules[1].Disabled {
		t.Errorf("rule not disabled after toggle")
	}
	if _, errMsg, code := toggleRuleDraft("rules.conf", 9999); errMsg != "no such rule" || code != 400 {
		t.Errorf("toggle missing: errMsg=%q code=%d", errMsg, code)
	}
	if _, errMsg, code := toggleRuleDraft("nope.conf", 1); errMsg != "unknown rule file" || code != 400 {
		t.Errorf("toggle unknown file: errMsg=%q code=%d", errMsg, code)
	}
	// move within the file: last rule to the top
	rules, _ = parseDraftRules(draftTextFor(*rf))
	if errMsg, _ := moveRuleDraft("rules.conf", "rules.conf", rules[2].ID, 0); errMsg != "" {
		t.Fatalf("move: %s", errMsg)
	}
	rules, _ = parseDraftRules(draftTextFor(*rf))
	if !strings.Contains(rules[0].Body, "3.3.3.3") {
		t.Errorf("move did not reorder: first body = %q", rules[0].Body)
	}
	if errMsg, code := moveRuleDraft("rules.conf", "rules.conf", 9999, 0); errMsg != "rule not found in source file" || code != 400 {
		t.Errorf("move missing: errMsg=%q code=%d", errMsg, code)
	}
	// delete the middle rule
	rules, _ = parseDraftRules(draftTextFor(*rf))
	if errMsg, _ := deleteRuleDraft("rules.conf", rules[1].ID); errMsg != "" {
		t.Fatalf("delete: %s", errMsg)
	}
	rules, _ = parseDraftRules(draftTextFor(*rf))
	if len(rules) != 2 {
		t.Errorf("delete: %d rules left, want 2", len(rules))
	}
	if errMsg, code := deleteRuleDraft("rules.conf", 9999); errMsg != "no such rule" || code != 400 {
		t.Errorf("delete missing: errMsg=%q code=%d", errMsg, code)
	}
}

func TestCommitApplyGuards(t *testing.T) {
	ruleTestEnv(t)
	// remove the seeded live rules file so no stage has a draft
	os.Remove(rulesFile)
	savedPending := pending
	t.Cleanup(func() { commitMu.Lock(); pending = savedPending; commitMu.Unlock() })

	if _, errMsg, code := commitApply(90); errMsg != "no draft to deploy" || code != 400 {
		t.Errorf("no drafts: errMsg=%q code=%d", errMsg, code)
	}
	os.WriteFile(sentinel, []byte("x"), 0644)
	if _, errMsg, code := commitApply(90); errMsg != "a confirm is already pending on the host" || code != 409 {
		t.Errorf("sentinel: errMsg=%q code=%d", errMsg, code)
	}
	os.Remove(sentinel)
	commitMu.Lock()
	pending.active = true
	commitMu.Unlock()
	if _, errMsg, code := commitApply(90); errMsg == "" || code != 409 {
		t.Errorf("pending: errMsg=%q code=%d", errMsg, code)
	}
	commitMu.Lock()
	pending.active = false
	commitMu.Unlock()

	for in, want := range map[int]int{0: 90, 19: 90, 20: 20, 90: 90, 600: 600, 601: 90, -5: 90} {
		if got := clampDeadman(in); got != want {
			t.Errorf("clampDeadman(%d) = %d, want %d", in, got, want)
		}
	}
}
