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

func TestLayoutCols(t *testing.T) {
	specs := []colSpec{{title: "a", min: 10}, {title: "b", min: 10, weight: 1}, {title: "c", min: 10, weight: 3}}
	// plenty of space: minimums + weighted split of the extra 40
	w := layoutCols(70, specs)
	if w[0] != 10 || w[1] != 20 || w[2] != 40 {
		t.Errorf("wide: %v, want [10 20 40]", w)
	}
	sum := w[0] + w[1] + w[2]
	if sum != 70 {
		t.Errorf("widths must consume the full total: %d != 70", sum)
	}
	// too narrow: minimums kept (degrade by clipping, not corruption)
	w = layoutCols(20, specs)
	if w[0] != 10 || w[1] != 10 || w[2] != 10 {
		t.Errorf("narrow: %v, want minimums", w)
	}
	// no flexible columns: extra space stays unused
	fixed := []colSpec{{title: "a", min: 5}, {title: "b", min: 5}}
	w = layoutCols(50, fixed)
	if w[0] != 5 || w[1] != 5 {
		t.Errorf("fixed: %v, want [5 5]", w)
	}
}

func TestObjectsTreeNavigation(t *testing.T) {
	m := initialModel()
	m.activeTab = 3
	m.objDrafts = [][]objEntry{
		{{Name: "G1", Members: []string{"1.1.1.1", "2.2.2.2"}}},
		{}, {}, {}, {}, {}, {},
	}

	press := func(k string) {
		var msg tea.KeyMsg
		switch k {
		case "enter":
			msg = tea.KeyMsg{Type: tea.KeyEnter}
		case "esc":
			msg = tea.KeyMsg{Type: tea.KeyEsc}
		default:
			msg = tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)}
		}
		res, _ := m.Update(msg)
		m = res.(cliModel)
	}

	// Enter descends Category -> Entry -> Member; Esc ascends.
	if m.objLevel != 0 {
		t.Fatalf("start at level 0, got %d", m.objLevel)
	}
	press("enter")
	if m.objLevel != 1 {
		t.Fatalf("enter should descend to entries, level = %d", m.objLevel)
	}
	press("enter")
	if m.objLevel != 2 {
		t.Fatalf("enter should descend to members, level = %d", m.objLevel)
	}
	press("esc")
	press("esc")
	if m.objLevel != 0 {
		t.Fatalf("esc should ascend back to categories, level = %d", m.objLevel)
	}

	// 'a' at entry level opens the input in add mode (the old build lost
	// these keys to tab-switch collisions — guard against regressing).
	press("enter")
	press("a")
	if !m.objInputMode || m.objInputContext != "entry_name" {
		t.Errorf("a should open add-entry input, mode=%v ctx=%q", m.objInputMode, m.objInputContext)
	}
	// esc closes the input without leaving the level
	press("esc")
	if m.objInputMode || m.objLevel != 1 {
		t.Errorf("esc should close input and stay at level 1, mode=%v level=%d", m.objInputMode, m.objLevel)
	}
	// tab still switches tabs from Objects (no h/l collision anymore)
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyTab})
	m = res.(cliModel)
	if m.activeTab != 4 {
		t.Errorf("tab should switch tabs, activeTab = %d", m.activeTab)
	}
}

func TestLogsDirectionCycle(t *testing.T) {
	m := initialModel()
	m.activeTab = 1
	press := func(k string) {
		res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(k)})
		m = res.(cliModel)
	}
	want := []string{"ingress", "egress", "forward", ""}
	for _, w := range want {
		press("f")
		if m.dirFilter != w {
			t.Fatalf("dirFilter = %q, want %q", m.dirFilter, w)
		}
	}
}

func TestQuitGuardedDuringConfirm(t *testing.T) {
	m := initialModel()
	m.editState = policyStateConfirming
	m.confirmRemaining = 42
	res, cmd := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("q")})
	m = res.(cliModel)
	if cmd != nil {
		t.Errorf("q must not quit while a deploy confirm is pending")
	}
	if m.statusMsg == "" || !m.statusErr {
		t.Errorf("expected a status-bar warning, got %q", m.statusMsg)
	}
}
