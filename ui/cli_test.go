package main

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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

func TestThemeCycling(t *testing.T) {
	m := initialModel()
	if !m.darkTheme {
		t.Errorf("Initial theme should be dark")
	}

	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
	m = res.(cliModel)
	if m.darkTheme {
		t.Errorf("Theme should be light after first toggle")
	}

	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("t")})
	m = res.(cliModel)
	if !m.darkTheme {
		t.Errorf("Theme should be dark after second toggle")
	}
}

func TestRefreshCycling(t *testing.T) {
	m := initialModel()
	m.refreshInterval = 5 * time.Second

	// 5s -> 10s
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("R")})
	m = res.(cliModel)
	if m.refreshInterval != 10*time.Second {
		t.Errorf("Expected 10s refresh, got %v", m.refreshInterval)
	}

	// 10s -> OFF
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("R")})
	m = res.(cliModel)
	if m.refreshInterval != 0 {
		t.Errorf("Expected OFF refresh, got %v", m.refreshInterval)
	}

	// OFF -> 2s
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("R")})
	m = res.(cliModel)
	if m.refreshInterval != 2*time.Second {
		t.Errorf("Expected 2s refresh, got %v", m.refreshInterval)
	}

	// 2s -> 5s
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("R")})
	m = res.(cliModel)
	if m.refreshInterval != 5*time.Second {
		t.Errorf("Expected 5s refresh, got %v", m.refreshInterval)
	}
}

func TestMouseTabSwitch(t *testing.T) {
	m := initialModel()
	m.activeTab = 0
	m.width = 80
	m.height = 24

	// Click on second tab "Logs"
	w1 := lipgloss.Width(m.styles.Tab.Render(m.tabs[0]))

	res, _ := m.Update(tea.MouseMsg{
		X:      w1 + 1,
		Y:      1,
		Action: tea.MouseActionPress,
		Button: tea.MouseButtonLeft,
	})
	m = res.(cliModel)

	if m.activeTab != 1 {
		t.Errorf("Expected active tab 1 (Logs), got %d", m.activeTab)
	}
}
