package main

import (
	"strings"
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

func TestLogsDetailAndWideFilter(t *testing.T) {
	m := initialModel()
	m.activeTab = 1
	m.drops = DropsResp{Recent: []Drop{
		{Time: "t1", Src: "1.1.1.1", Dst: "9.9.9.9", Dport: "443", Proto: "TCP", Dir: "ingress", CC: "de", Reason: "geo", Verdict: "drop"},
		{Time: "t2", Src: "2.2.2.2", Dst: "8.8.8.8", Dport: "22", Proto: "TCP", Dir: "ingress", CC: "us", Reason: "abuse", Verdict: "drop"},
	}}

	// the text filter must match destination, port and country too
	for filter, want := range map[string]int{"9.9.9.9": 1, "443": 1, "de": 1, "abuse": 1, "nomatch": 0} {
		m.filterInput.SetValue(filter)
		m.updateData()
		if got := len(m.logTable.Rows()); got != want {
			t.Errorf("filter %q: %d rows, want %d", filter, got, want)
		}
	}
	m.filterInput.SetValue("")
	m.updateData()

	// Enter opens the detail modal for the selected (filtered) record
	res, cmd := m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(cliModel)
	if m.modal != modalLookup || m.detailDrop == nil {
		t.Fatalf("enter should open the detail modal with the record")
	}
	if m.detailDrop.Src != "1.1.1.1" || m.detailDrop.Dst != "9.9.9.9" {
		t.Errorf("wrong record in detail: %+v", m.detailDrop)
	}
	if cmd == nil {
		t.Errorf("enter should start the async PTR/RDAP lookup")
	}
	// esc closes and clears the record
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = res.(cliModel)
	if m.modal != modalNone || m.detailDrop != nil {
		t.Errorf("esc should close the modal and clear the record")
	}
}

func TestDashboardTopPanels(t *testing.T) {
	// sortedCounts: descending, ties alphabetical, capped at limit
	got := sortedCounts(map[string]int{"us": 5, "de": 9, "pl": 5, "fr": 1}, 3)
	if len(got) != 3 || got[0].label != "de" || got[1].label != "pl" || got[2].label != "us" {
		t.Errorf("sortedCounts = %+v", got)
	}
	// miniHistogram: scales to its own max, empty-safe
	if h := miniHistogram([]int{0, 1, 8}); len([]rune(h)) != 3 {
		t.Errorf("miniHistogram len = %q", h)
	}
	if h := miniHistogram(nil); h != "" {
		t.Errorf("empty buckets: %q", h)
	}
	// topPanel renders every row with a visible bar
	m := initialModel()
	out := m.topPanel("T", []kvCount{{"us", 100}, {"pl", 1}}, 40, m.styles.Accent)
	if !strings.Contains(out, "us") || !strings.Contains(out, "pl") || !strings.Contains(out, "▇") {
		t.Errorf("topPanel output missing rows/bars:\n%s", out)
	}
}

func TestRuleFormReqMapping(t *testing.T) {
	m := initialModel()
	// filter form -> ruleSaveReq (no Kind; dispatched by Action)
	m.openRuleForm("filter", nil, "rules.conf")
	set := func(key, val string) {
		for i := range m.ruleForm.fields {
			if m.ruleForm.fields[i].key == key {
				m.ruleForm.fields[i].input.SetValue(val)
			}
		}
	}
	set("action", "deny")
	set("dir", "in")
	set("proto", "tcp")
	set("port", "22")
	set("target", "abuse")
	set("log", "y")
	req := m.ruleForm.formReq()
	if req.Kind != "" || req.Action != "deny" || req.Port != "22" || req.Target != "abuse" || !req.Log {
		t.Errorf("filter req = %+v", req)
	}

	// throttle -> Action forced to "throttle"
	m.openRuleForm("throttle", nil, "rules.conf")
	req = m.ruleForm.formReq()
	if req.Action != "throttle" {
		t.Errorf("throttle req.Action = %q, want throttle", req.Action)
	}

	// nat -> Kind carried through so saveRuleDraft dispatches to buildNatBody
	m.openRuleForm("nat", nil, "rules.conf")
	req = m.ruleForm.formReq()
	if req.Kind != "nat" {
		t.Errorf("nat req.Kind = %q, want nat", req.Kind)
	}

	// edit prefills and carries the ID
	id := 7
	edit := &draftRule{ID: id, File: "rules.conf", Action: "allow", Dir: "in", Proto: "udp", Port: "53", Target: "any", Name: "dns"}
	m.openRuleForm("filter", edit, "rules.conf")
	req = m.ruleForm.formReq()
	if req.ID == nil || *req.ID != id || req.Proto != "udp" || req.Name != "dns" {
		t.Errorf("edit req = %+v (id=%v)", req, req.ID)
	}
}

func TestPolicyDeleteConfirm(t *testing.T) {
	m := initialModel()
	m.activeTab = 2
	m.draftRules = []*draftRule{{ID: 3, File: "rules.conf", Body: "drop any", Action: "deny"}}
	m.updateData()
	m.policyTable.SetCursor(0)

	// 'd' arms the confirm, does not delete yet
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("d")})
	m = res.(cliModel)
	if m.deleteTarget == nil || m.deleteTarget.ID != 3 {
		t.Fatalf("d should arm delete confirm, got %v", m.deleteTarget)
	}
	// any non-y cancels
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("n")})
	m = res.(cliModel)
	if m.deleteTarget != nil {
		t.Errorf("n should cancel the delete confirm")
	}
}

func TestPolicyAddOpensPicker(t *testing.T) {
	m := initialModel()
	m.activeTab = 2
	res, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("a")})
	m = res.(cliModel)
	if !m.ruleForm.active || !m.ruleForm.picker {
		t.Fatalf("a should open the kind picker, form=%+v", m.ruleForm)
	}
	// picking a kind opens the field form
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEnter})
	m = res.(cliModel)
	if m.ruleForm.picker || len(m.ruleForm.fields) == 0 {
		t.Errorf("enter should open the field form, form=%+v", m.ruleForm)
	}
	// esc closes it
	res, _ = m.Update(tea.KeyMsg{Type: tea.KeyEsc})
	m = res.(cliModel)
	if m.ruleForm.active {
		t.Errorf("esc should close the form")
	}
}

func TestReferenceWhitelistEdit(t *testing.T) {
	dir := t.TempDir()
	oldD, oldWL, oldWLH := draftDir, wlDraftFile, wlHostsDraftFile
	draftDir = dir
	wlDraftFile = dir + "/whitelist"
	wlHostsDraftFile = dir + "/whitelist-hosts"
	t.Cleanup(func() { draftDir, wlDraftFile, wlHostsDraftFile = oldD, oldWL, oldWLH })

	m := initialModel()
	m.activeTab = 3
	m.wlEntries = []string{"10.0.0.1"}
	m.wlHosts = nil

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

	// w enters Reference; a opens the add input
	press("w")
	if !m.objRef {
		t.Fatalf("w should toggle Reference on")
	}
	press("a")
	if !m.refAddMode {
		t.Fatalf("a should open the whitelist add input")
	}
	// type a valid CIDR and confirm — it is saved through saveWhitelistDraft
	m.objInput.SetValue("192.168.5.0/24")
	press("enter")
	if m.refAddMode {
		t.Errorf("enter should close the add input")
	}
	if len(m.wlEntries) != 2 || m.wlEntries[1] != "192.168.5.0/24" {
		t.Fatalf("entry not added: %v", m.wlEntries)
	}
	if got := readFileStr(wlDraftFile); got != serializeListFile(m.wlEntries) {
		t.Errorf("whitelist draft not written by the shared path: %q", got)
	}

	// invalid entry surfaces the validation error and does not persist a draft
	m.setStatusInfo("")
	press("a")
	m.objInput.SetValue("not-an-ip")
	press("enter")
	if !m.statusErr {
		t.Errorf("invalid whitelist entry should raise a status error")
	}

	// d deletes the selected entry
	m.wlEntries = []string{"10.0.0.1", "192.168.5.0/24"}
	m.refSel = 0
	press("d")
	if len(m.wlEntries) != 1 || m.wlEntries[0] != "192.168.5.0/24" {
		t.Errorf("delete failed: %v", m.wlEntries)
	}
}
