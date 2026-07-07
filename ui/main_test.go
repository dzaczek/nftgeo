package main

import "testing"

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
