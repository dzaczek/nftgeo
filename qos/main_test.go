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
