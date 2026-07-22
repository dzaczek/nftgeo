package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseConfigAndPlan(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "qos.conf")
	if err := os.WriteFile(p, []byte("enabled yes\ninterface eth0\nbandwidth 100mbit\ndefault standard\nclass voice mark 10 rate 20% ceil 100% priority 0\nclass standard mark 20 rate 40mbit ceil 100% priority 3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := parseConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if c.Classes[0].Rate != "20000000bit" || c.Classes[1].Ceil != "100000000bit" {
		t.Fatalf("rates not resolved: %#v", c.Classes)
	}
	plan := tcPlan(c, "tc")
	got := strings.Join(plan[len(plan)-1], " ")
	if !strings.Contains(got, "handle 20 fw flowid 1:11") {
		t.Fatalf("mark filter missing: %s", got)
	}
}

func TestRejectsInvalidQoS(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "qos.conf")
	if err := os.WriteFile(p, []byte("enabled yes\ninterface eth0\nbandwidth 10mbit\ndefault no\nclass x mark 1 rate 90% ceil 20%\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig(p); err == nil {
		t.Fatal("invalid profile accepted")
	}
}

func TestParseConfigMultiInterface(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "qos.conf")
	configStr := `enabled yes
interface eth0 takeover
direction upload
bandwidth 100mbit
default standard
class voice mark 10 rate 20% ceil 100% priority 0
class standard mark 20 rate 40mbit ceil 100% priority 3

interface eth1
direction download
bandwidth 50mbit
default bulk
class bulk mark 30 rate 10mbit ceil 100% priority 7
`
	if err := os.WriteFile(p, []byte(configStr), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := parseConfig(p)
	if err != nil {
		t.Fatal(err)
	}

	if len(c.Interfaces) != 2 {
		t.Fatalf("expected 2 interfaces, got %d", len(c.Interfaces))
	}
	if c.Interfaces[0].Name != "eth0" || !c.Interfaces[0].Takeover {
		t.Fatalf("first interface should be eth0 with takeover")
	}
	if c.Interfaces[1].Name != "eth1" || c.Interfaces[1].Takeover {
		t.Fatalf("second interface should be eth1 without takeover")
	}

	plan := tcPlan(c, "tc")
	hasIFBSetup := false
	hasCake := false
	for _, cmd := range plan {
		cmdStr := strings.Join(cmd, " ")
		if strings.Contains(cmdStr, "ip link add name ifb-eth1 type ifb") {
			hasIFBSetup = true
		}
		if strings.Contains(cmdStr, "cake") {
			hasCake = true
		}
	}
	if !hasIFBSetup {
		t.Fatal("expected IFB environment setup command lines for eth1 download")
	}
	if hasCake {
		t.Fatal("no cake expected in this plan")
	}
}

func TestParseConfigCake(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "qos.conf")
	configStr := `enabled yes
interface eth0
direction upload
bandwidth 100mbit
qdisc cake
overhead ethernet
default unused
class voice mark 10 rate 20% ceil 100% priority 0
`
	if err := os.WriteFile(p, []byte(configStr), 0600); err != nil {
		t.Fatal(err)
	}
	c, err := parseConfig(p)
	if err != nil {
		t.Fatal(err)
	}

	plan := tcPlan(c, "tc")
	hasCakeOverhead := false
	for _, cmd := range plan {
		cmdStr := strings.Join(cmd, " ")
		if strings.Contains(cmdStr, "cake bandwidth 100mbit overhead ethernet") {
			hasCakeOverhead = true
		}
	}
	if !hasCakeOverhead {
		t.Fatal("expected cake with overhead config in plan")
	}
}

func TestAggregateGuaranteeCheck(t *testing.T) {
	d := t.TempDir()
	p := filepath.Join(d, "qos.conf")
	configStr := `enabled yes
interface eth0
direction upload
bandwidth 10mbit
default standard
class voice mark 10 rate 8mbit ceil 100% priority 0
class standard mark 20 rate 4mbit ceil 100% priority 3
`
	if err := os.WriteFile(p, []byte(configStr), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseConfig(p); err == nil {
		t.Fatal("expected rejection since aggregate guarantees (12mbit) exceed bandwidth (10mbit)")
	}
}

func TestParseClassStats(t *testing.T) {
	output := `class htb 1:10 parent 1:1 leaf 10: prio 0 rate 20Mbit ceil 100Mbit burst 1600b cburst 1600b
 Sent 123456 bytes 789 pkt (dropped 12, overlimits 34 requeues 0)
 backlog 50b 0p requeues 0`
	stats := parseClassStats(output)
	if len(stats) != 1 {
		t.Fatalf("expected 1 class stats, got %d", len(stats))
	}
	s, exists := stats["1:10"]
	if !exists {
		t.Fatal("expected stats for class 1:10")
	}
	if s.SentBytes != 123456 || s.SentPkts != 789 || s.Dropped != 12 || s.Overlimits != 34 || s.Backlog != 50 {
		t.Fatalf("incorrect parsed stats: %+v", s)
	}
}

func TestParseQdiscStats(t *testing.T) {
	output := `qdisc htb 1: root refcnt 2 bands 3
 Sent 999 bytes 10 pkt (dropped 1, overlimits 2)
 backlog 0b 0p`
	stats := parseQdiscStats(output)
	if len(stats) != 1 {
		t.Fatalf("expected 1 qdisc stats, got %d", len(stats))
	}
	s, exists := stats["1:"]
	if !exists {
		t.Fatal("expected stats for qdisc 1:")
	}
	if s.SentBytes != 999 || s.SentPkts != 10 || s.Dropped != 1 || s.Overlimits != 2 {
		t.Fatalf("incorrect parsed stats: %+v", s)
	}
}

func TestDetectDrift(t *testing.T) {
	dirConf := directionConfig{
		Qdisc: "htb",
		Classes: []class{
			{Name: "voice", ID: 11, Mark: 10, Rate: "2mbit", Ceil: "10mbit"},
		},
	}
	// No drift case
	liveClasses := map[string]ClassStats{
		"1:11": {ClassID: "1:11"}, // 10 + idx
	}
	liveQdiscs := map[string]QdiscStats{
		"1:": {QdiscType: "htb"},
	}
	if detectDriftForDirection(dirConf, liveClasses, liveQdiscs) {
		t.Fatal("expected no drift")
	}

	// Drift case: class missing
	emptyClasses := map[string]ClassStats{}
	if !detectDriftForDirection(dirConf, emptyClasses, liveQdiscs) {
		t.Fatal("expected drift due to missing class")
	}

	// Drift case: qdisc type mismatch
	wrongQdiscs := map[string]QdiscStats{
		"1:": {QdiscType: "cake"},
	}
	if !detectDriftForDirection(dirConf, liveClasses, wrongQdiscs) {
		t.Fatal("expected drift due to qdisc mismatch")
	}
}
