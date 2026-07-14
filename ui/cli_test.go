package main

import (
	"testing"
)

func TestFormatBpsVal(t *testing.T) {
	tests := []struct {
		val  float64
		want string
	}{
		{0, "0 bps"},
		{500, "500 bps"},
		{1000, "1000 bps"},
		{1001, "1.0 Kbps"},
		{1500, "1.5 Kbps"},
		{1000000, "1000.0 Kbps"},
		{1000001, "1.0 Mbps"},
		{2500000, "2.5 Mbps"},
	}

	for _, tt := range tests {
		if got := formatBpsVal(tt.val); got != tt.want {
			t.Errorf("formatBpsVal(%v) = %q, want %q", tt.val, got, tt.want)
		}
	}
}

func TestUpdateDataFilter(t *testing.T) {
	m := initialModel()
	m.drops = DropsResp{
		Recent: []Drop{
			{Verdict: "drop", Dir: "ingress", Src: "1.1.1.1", Reason: "abuse"},
			{Verdict: "accept", Dir: "ingress", Src: "2.2.2.2", Reason: "allow"},
			{Verdict: "drop", Dir: "egress", Src: "3.3.3.3", Reason: "out-block"},
		},
	}

	// Test verdict filter
	m.verdictFilter = "drop"
	m.updateData()
	if len(m.logTable.Rows()) != 2 {
		t.Errorf("Verdict=drop filter failed, got %d rows, want 2", len(m.logTable.Rows()))
	}

	// Test direction filter
	m.verdictFilter = ""
	m.dirFilter = "egress"
	m.updateData()
	if len(m.logTable.Rows()) != 1 {
		t.Errorf("Dir=egress filter failed, got %d rows, want 1", len(m.logTable.Rows()))
	}

	// Test text search
	m.dirFilter = ""
	m.filterInput.SetValue("1.1.1.1")
	m.updateData()
	if len(m.logTable.Rows()) != 1 {
		t.Errorf("Text search filter failed, got %d rows, want 1", len(m.logTable.Rows()))
	}
}
