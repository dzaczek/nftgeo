package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
		{"tcp_noport", "allow", "in", "tcp", "", "any", "", "", true},
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
	cases := map[string]string{
		"nftgeo-drop:abuse IN=eth0 SRC=1.2.3.4 DPT=22": "abuse",
		"nftgeo-drop:block others IN=eth0 SRC=1.2.3.4": "block others",
		"nftgeo-drop:default-deny IN=eth0 SRC=9.9.9.9": "default-deny",
		"nftgeo-drop:geo IN=eth0 SRC=1.2.3.4":          "geo",
		"nftgeo-drop IN=eth0 SRC=1.2.3.4":              "", // old prefix, no reason
	}
	for msg, want := range cases {
		got := ""
		if m := reReason.FindStringSubmatch(msg); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", msg, got, want)
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
	g, r, s, h, z := parseObjects(`GROUP_OFFICE="10.0.0.0/24 1.2.3.4"` + "\n" + `REGION_BLK="ru cn"` + "\n" + `SERVICE_WEB="80 443/tcp"` + "\n" + `HOST_DB1="10.0.0.5"` + "\n" + `ZONE_GUEST="eth1 eth0.100"` + "\n")
	if len(g) != 1 || len(r) != 1 || len(s) != 1 || len(h) != 1 || len(z) != 1 {
		t.Fatalf("counts g=%d r=%d s=%d h=%d z=%d", len(g), len(r), len(s), len(h), len(z))
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
	out := serializeObjects(g, r, s, h, z)
	g2, r2, s2, h2, z2 := parseObjects(out)
	if len(g2) != 1 || len(r2) != 1 || len(s2) != 1 || len(h2) != 1 || len(z2) != 1 {
		t.Errorf("re-parse of serialized objects lost entries: %q", out)
	}
}

func TestSanitizeObjectsRejectsInjection(t *testing.T) {
	if err := sanitizeObjects([]objEntry{{Name: "X", Members: []string{"1.2.3.4; rm"}}}, nil, nil, nil, nil); err == nil {
		t.Error("expected shell-metachar member to be rejected")
	}
	if err := sanitizeObjects([]objEntry{{Name: "bad name", Members: nil}}, nil, nil, nil, nil); err == nil {
		t.Error("expected invalid name to be rejected")
	}
	if err := sanitizeObjects([]objEntry{{Name: "OK", Members: []string{"80", "443/tcp"}}}, nil, nil, nil, nil); err != nil {
		t.Errorf("valid service members rejected: %v", err)
	}
	// zone interface members: VLAN subif OK, shell metachars rejected
	if err := sanitizeObjects(nil, nil, nil, nil, []objEntry{{Name: "GUEST", Members: []string{"eth0.100", "br-lan"}}}); err != nil {
		t.Errorf("valid zone interfaces rejected: %v", err)
	}
	if err := sanitizeObjects(nil, nil, nil, nil, []objEntry{{Name: "Z", Members: []string{"eth0; rm"}}}); err == nil {
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
