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
	if r.Kind != "rule" || r.Action != "allow" || r.Dir != "in" || r.Port != "22" || r.Name != "ssh" {
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

func TestObjectsRoundTrip(t *testing.T) {
	g, r, s := parseObjects(`GROUP_OFFICE="10.0.0.0/24 1.2.3.4"` + "\n" + `REGION_BLK="ru cn"` + "\n" + `SERVICE_WEB="80 443/tcp"` + "\n")
	if len(g) != 1 || len(r) != 1 || len(s) != 1 {
		t.Fatalf("counts g=%d r=%d s=%d", len(g), len(r), len(s))
	}
	if g[0].Name != "OFFICE" || len(g[0].Members) != 2 || g[0].Members[1] != "1.2.3.4" {
		t.Errorf("group parsed wrong: %+v", g[0])
	}
	if s[0].Name != "WEB" || s[0].Members[1] != "443/tcp" {
		t.Errorf("service parsed wrong: %+v", s[0])
	}
	out := serializeObjects(g, r, s)
	g2, r2, s2 := parseObjects(out)
	if len(g2) != 1 || len(r2) != 1 || len(s2) != 1 {
		t.Errorf("re-parse of serialized objects lost entries: %q", out)
	}
}

func TestSanitizeObjectsRejectsInjection(t *testing.T) {
	if err := sanitizeObjects([]objEntry{{Name: "X", Members: []string{"1.2.3.4; rm"}}}, nil, nil); err == nil {
		t.Error("expected shell-metachar member to be rejected")
	}
	if err := sanitizeObjects([]objEntry{{Name: "bad name", Members: nil}}, nil, nil); err == nil {
		t.Error("expected invalid name to be rejected")
	}
	if err := sanitizeObjects([]objEntry{{Name: "OK", Members: []string{"80", "443/tcp"}}}, nil, nil); err != nil {
		t.Errorf("valid service members rejected: %v", err)
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
