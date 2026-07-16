package main

// Policy view: the draft rules table with full authoring — add/edit forms for
// every rule kind (filter, throttle, synproxy, NAT, zone, ingress), delete
// with confirm, enable/disable, grab-move, and a rule detail modal. Every
// mutation goes through the shared draft functions (saveRuleDraft,
// deleteRuleDraft, toggleRuleDraft, moveRuleDraft) — the same code the web
// handlers call, validated by the same build*Body builders.
//
// Table cells are deliberately plain text: this bubbles version truncates
// cells by byte-ish width, so ANSI-styled cell values get cut early (the old
// "dro…" verdicts). Row emphasis uses markers (▶, "## ") instead of color.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	bubblesTable "github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type policyKeyMap struct {
	Toggle key.Binding
	Move   key.Binding
	Add    key.Binding
	Edit   key.Binding
	Delete key.Binding
}

var policyKeys = policyKeyMap{
	Toggle: key.NewBinding(key.WithKeys(" "), key.WithHelp("space", "enable/disable")),
	Move:   key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "move")),
	Add:    key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "add rule")),
	Edit:   key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "edit rule")),
	Delete: key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "delete rule")),
}

const policyHints = "enter detail · a add · e edit · d delete · space toggle · m move · r discard"

var policyColSpecs = []colSpec{
	{title: "#", min: 4},
	{title: "Kind", min: 8},
	{title: "Action", min: 10},
	{title: "Dir", min: 6},
	{title: "Proto", min: 5},
	{title: "Port", min: 8},
	{title: "Target", min: 14, weight: 3},
	{title: "Iface", min: 7},
	{title: "Hits", min: 8},
	{title: "Activity", min: 10, weight: 1},
}

func policyColumns(width int) []bubblesTable.Column {
	return toTableColumns(policyColSpecs, layoutCols(width-2*len(policyColSpecs), policyColSpecs))
}

func (m *cliModel) updatePolicyData() {
	var pRows []bubblesTable.Row
	maxHits := 1.0
	for _, r := range m.draftRules {
		if float64(r.Hits) > maxHits {
			maxHits = float64(r.Hits)
		}
	}

	for _, r := range m.draftRules {
		if r.Kind == "section" {
			pRows = append(pRows, bubblesTable.Row{
				"", "", "", "", "", "", "## " + r.Title, "", "", "",
			})
			continue
		}

		hits := fmt.Sprintf("%d", r.Hits)
		if r.Hits > 1000 {
			hits = fmt.Sprintf("%.1fk", float64(r.Hits)/1000)
		}

		bar := ""
		if r.Matched && r.Hits > 0 && !r.Disabled {
			w := int(float64(r.Hits) / maxHits * 10)
			if w < 1 {
				w = 1
			}
			bar = strings.Repeat("■", w)
		}

		id := fmt.Sprintf("%d", r.ID)
		if m.editState == policyStateMoving && m.moveSourceID == r.ID {
			id = "▶" + id
		}
		action := r.Action
		if r.Disabled {
			action = "✗ " + r.Action
		}
		kind := r.Kind
		if kind == "" {
			kind = "filter"
		}

		pRows = append(pRows, bubblesTable.Row{
			id, kind, action, r.Dir, r.Proto, r.Port, r.Target, r.Iface, hits, bar,
		})
	}
	m.policyTable.SetRows(pRows)
	if c := m.policyTable.Cursor(); len(pRows) > 0 && (c < 0 || c >= len(pRows)) {
		if c < 0 {
			m.policyTable.SetCursor(0)
		} else {
			m.policyTable.SetCursor(len(pRows) - 1)
		}
	}
}

// ---- add/edit form ----

// ruleFormField feeds one ruleSaveReq field from a text input.
type ruleFormField struct {
	key   string // ruleSaveReq field name (lower-case)
	label string
	hint  string
	input textinput.Model
}

type ruleFormState struct {
	active    bool
	picker    bool // choosing the kind (add flow)
	pickerIdx int
	kind      string // filter | throttle | synproxy | nat | zone | ingress
	editID    *int   // nil = append new
	file      string
	fields    []ruleFormField
	focus     int
}

var ruleKinds = []string{"filter", "throttle", "synproxy", "nat", "zone", "ingress"}

// ruleFormSpecs defines the fields each kind's builder validates.
var ruleFormSpecs = map[string][][3]string{ // key, label, hint
	"filter": {
		{"action", "Action", "allow | deny"},
		{"dir", "Dir", "in | out"},
		{"proto", "Proto", "tcp | udp | any"},
		{"port", "Port", "22, 80,443, web — empty = all"},
		{"target", "Target", "any | IP/CIDR | group | region | abuse"},
		{"iface", "Iface", "optional, e.g. eth0"},
		{"log", "Log", "y = log connections"},
		{"name", "Name", "optional comment"},
	},
	"throttle": {
		{"dir", "Dir", "in | fwd-in"},
		{"proto", "Proto", "tcp | udp"},
		{"port", "Port", "e.g. 22"},
		{"rate", "Rate", "e.g. 5/minute"},
		{"ban", "Ban", "optional, e.g. 2h"},
		{"iface", "Iface", "optional"},
		{"name", "Name", "optional comment"},
	},
	"synproxy": {
		{"dir", "Dir", "in"},
		{"port", "Port", "e.g. 443"},
		{"iface", "Iface", "optional"},
		{"name", "Name", "optional comment"},
	},
	"nat": {
		{"nattype", "Type", "masquerade | snat | dnat"},
		{"proto", "Proto", "tcp | udp"},
		{"port", "Port", "e.g. 8080 or 8080:80"},
		{"target", "Target", "dnat: destination IP[:port]; snat: source IP"},
		{"geo", "Geo", "optional region filter"},
		{"iface", "Iface", "optional WAN iface"},
		{"lan", "Lan", "optional LAN iface"},
		{"name", "Name", "optional comment"},
	},
	"zone": {
		{"action", "Action", "allow | deny"},
		{"src", "From", "source zone"},
		{"dst", "To", "destination zone"},
		{"proto", "Proto", "tcp | udp | any"},
		{"port", "Port", "optional"},
		{"geo", "Geo", "optional region filter"},
		{"name", "Name", "optional comment"},
	},
	"ingress": {
		{"action", "Action", "accept | drop"},
		{"target", "Target", "any | IP/CIDR | abuse | group"},
		{"proto", "Proto", "tcp | udp"},
		{"port", "Port", "optional"},
		{"log", "Log", "y = log"},
		{"name", "Name", "optional comment"},
	},
}

// openRuleForm builds the form for a kind, prefilled from an existing rule
// when editing.
func (m *cliModel) openRuleForm(kind string, edit *draftRule, file string) {
	f := ruleFormState{active: true, kind: kind, file: file}
	if edit != nil {
		id := edit.ID
		f.editID = &id
		f.file = edit.File
	}
	prefill := map[string]string{}
	if edit != nil {
		logVal := ""
		if edit.Log {
			logVal = "y"
		}
		prefill = map[string]string{
			"action": edit.Action, "dir": edit.Dir, "proto": edit.Proto,
			"port": edit.Port, "target": edit.Target, "iface": edit.Iface,
			"rate": edit.Rate, "ban": edit.Ban, "src": edit.Src, "dst": edit.Dst,
			"geo": edit.Geo, "nattype": edit.NatType, "lan": edit.Lan,
			"log": logVal, "name": edit.Name,
		}
	}
	for _, spec := range ruleFormSpecs[kind] {
		ti := textinput.New()
		ti.CharLimit = 64
		ti.Width = 28
		ti.Prompt = ""
		ti.SetValue(prefill[spec[0]])
		f.fields = append(f.fields, ruleFormField{key: spec[0], label: spec[1], hint: spec[2], input: ti})
	}
	if len(f.fields) > 0 {
		f.fields[0].input.Focus()
	}
	m.ruleForm = f
}

// formReq assembles the shared ruleSaveReq from the form fields.
func (f *ruleFormState) formReq() ruleSaveReq {
	req := ruleSaveReq{File: f.file, ID: f.editID}
	switch f.kind {
	case "filter", "throttle":
		// dispatched by Action ("throttle") or default filter path
	default:
		req.Kind = f.kind
	}
	if f.kind == "throttle" {
		req.Action = "throttle"
	}
	get := func(key string) string {
		for _, fl := range f.fields {
			if fl.key == key {
				return strings.TrimSpace(fl.input.Value())
			}
		}
		return ""
	}
	if v := get("action"); v != "" {
		req.Action = v
	}
	req.Dir = get("dir")
	req.Proto = get("proto")
	req.Port = get("port")
	req.Target = get("target")
	req.Iface = get("iface")
	req.Rate = get("rate")
	req.Ban = get("ban")
	req.Src = get("src")
	req.Dst = get("dst")
	req.Geo = get("geo")
	req.NatType = get("nattype")
	req.Lan = get("lan")
	req.Name = get("name")
	req.Log = strings.HasPrefix(strings.ToLower(get("log")), "y")
	return req
}

// updateRuleForm owns the keyboard while the add/edit form (or the kind
// picker) is open.
func (m cliModel) updateRuleForm(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	f := &m.ruleForm

	if f.picker {
		switch {
		case key.Matches(msg, viewKeyBack):
			m.ruleForm = ruleFormState{}
			return m, nil
		case key.Matches(msg, viewKeyUp):
			if f.pickerIdx > 0 {
				f.pickerIdx--
			}
			return m, nil
		case key.Matches(msg, viewKeyDown):
			if f.pickerIdx < len(ruleKinds)-1 {
				f.pickerIdx++
			}
			return m, nil
		case key.Matches(msg, viewKeyEnter):
			file := f.file
			m.openRuleForm(ruleKinds[f.pickerIdx], nil, file)
			return m, nil
		}
		return m, nil
	}

	switch msg.String() {
	case "esc":
		m.ruleForm = ruleFormState{}
		return m, nil
	case "enter":
		req := f.formReq()
		if errMsg, _ := saveRuleDraft(req); errMsg != "" {
			m.setStatusErr(errMsg)
			return m, nil // keep the form open so the input can be fixed
		}
		verb := "added"
		if f.editID != nil {
			verb = "updated"
		}
		m.setStatusInfo(fmt.Sprintf("%s rule %s — c to commit", f.kind, verb))
		m.ruleForm = ruleFormState{}
		return m, fetchDataCmd()
	case "tab", "down":
		f.fields[f.focus].input.Blur()
		f.focus = (f.focus + 1) % len(f.fields)
		f.fields[f.focus].input.Focus()
		return m, nil
	case "shift+tab", "up":
		f.fields[f.focus].input.Blur()
		f.focus = (f.focus - 1 + len(f.fields)) % len(f.fields)
		f.fields[f.focus].input.Focus()
		return m, nil
	}
	f.fields[f.focus].input, cmd = f.fields[f.focus].input.Update(msg)
	return m, cmd
}

// renderRuleForm renders the kind picker or the field form.
func (m cliModel) renderRuleForm() string {
	f := m.ruleForm
	var b strings.Builder
	if f.picker {
		b.WriteString(m.styles.PanelTitle.Render("Add rule — pick a type") + "\n\n")
		for i, k := range ruleKinds {
			cursor := "  "
			line := k
			if i == f.pickerIdx {
				cursor = m.styles.Accent.Render("▶ ")
				line = m.styles.Accent.Copy().Bold(true).Render(k)
			}
			b.WriteString(cursor + line + "\n")
		}
		b.WriteString("\n" + m.styles.Muted.Render("enter select · esc cancel"))
		return b.String()
	}

	title := "Add " + f.kind + " rule"
	if f.editID != nil {
		title = fmt.Sprintf("Edit %s rule #%d", f.kind, *f.editID)
	}
	b.WriteString(m.styles.PanelTitle.Render(title+" → "+f.file) + "\n\n")
	for i, fl := range f.fields {
		label := fmt.Sprintf("  %-8s ", fl.label)
		if i == f.focus {
			label = m.styles.Accent.Copy().Bold(true).Render(fmt.Sprintf("▶ %-8s ", fl.label))
		} else {
			label = m.styles.Muted.Render(label)
		}
		b.WriteString(label + fl.input.View())
		if i == f.focus {
			b.WriteString("   " + m.styles.Muted.Render(fl.hint))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n" + m.styles.Muted.Render("enter save · tab/↑↓ fields · esc cancel"))
	return b.String()
}

// renderRuleDetail renders the full parsed rule for the detail modal.
func (m cliModel) renderRuleDetail(r *draftRule) string {
	label := m.styles.Muted
	kind := r.Kind
	if kind == "" {
		kind = "filter"
	}
	state := "enabled"
	if r.Disabled {
		state = "DISABLED"
	}
	matched := "no"
	if r.Matched {
		matched = "yes"
	}
	var b strings.Builder
	b.WriteString(m.styles.PanelTitle.Render(fmt.Sprintf("Rule #%d (%s)", r.ID, kind)) + "\n\n")
	b.WriteString(label.Render("  Body:     ") + r.Body + "\n")
	if r.Name != "" {
		b.WriteString(label.Render("  Name:     ") + r.Name + "\n")
	}
	b.WriteString(label.Render("  File:     ") + r.File + "\n")
	b.WriteString(label.Render("  State:    ") + state + "\n")
	b.WriteString(label.Render("  Hits:     ") + fmt.Sprintf("%d (in ruleset: %s)", r.Hits, matched) + "\n")
	b.WriteString("\n" + m.styles.Muted.Render("e edit · d delete · space toggle · esc close"))
	return b.String()
}

// selectedRule maps the table cursor to the underlying draft rule.
func (m *cliModel) selectedRule() *draftRule {
	idx := m.policyTable.Cursor()
	if idx >= 0 && idx < len(m.draftRules) {
		return m.draftRules[idx]
	}
	return nil
}

func (m cliModel) updatePolicyKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	// delete confirmation owns y/n while armed
	if m.deleteTarget != nil {
		switch msg.String() {
		case "y":
			if errMsg, _ := deleteRuleDraft(m.deleteTarget.File, m.deleteTarget.ID); errMsg != "" {
				m.setStatusErr(errMsg)
			} else {
				m.setStatusInfo(fmt.Sprintf("rule #%d deleted — c to commit", m.deleteTarget.ID))
			}
			m.deleteTarget = nil
			return m, fetchDataCmd()
		default:
			m.deleteTarget = nil
			m.setStatusInfo("delete cancelled")
			return m, nil
		}
	}

	switch {
	case key.Matches(msg, policyKeys.Toggle):
		if m.editState == policyStateNormal {
			if r := m.selectedRule(); r != nil && r.Kind != "section" {
				if _, errMsg, _ := toggleRuleDraft(r.File, r.ID); errMsg != "" {
					m.setStatusErr(errMsg)
				}
				return m, fetchDataCmd()
			}
		}
		return m, nil

	case key.Matches(msg, policyKeys.Move):
		if len(m.draftRules) > 0 && m.editState == policyStateNormal {
			if r := m.selectedRule(); r != nil && r.Kind != "section" {
				m.editState = policyStateMoving
				m.moveSourceID = r.ID
				m.updateData() // show the ▶ marker immediately
			}
		}
		return m, nil

	case key.Matches(msg, policyKeys.Add):
		if m.editState == policyStateNormal {
			file := "rules.conf"
			if r := m.selectedRule(); r != nil {
				file = r.File
			}
			m.ruleForm = ruleFormState{active: true, picker: true, file: file}
		}
		return m, nil

	case key.Matches(msg, policyKeys.Edit):
		if m.editState == policyStateNormal {
			if r := m.selectedRule(); r != nil && r.Kind != "section" {
				kind := r.Kind
				if kind == "" {
					kind = "filter"
				}
				if kind == "throttle" || r.Action == "throttle" {
					kind = "throttle"
				}
				if _, ok := ruleFormSpecs[kind]; !ok {
					m.setStatusErr("cannot edit " + kind + " rules yet")
					return m, nil
				}
				m.openRuleForm(kind, r, r.File)
			}
		}
		return m, nil

	case key.Matches(msg, policyKeys.Delete):
		if m.editState == policyStateNormal {
			if r := m.selectedRule(); r != nil && r.Kind != "section" {
				m.deleteTarget = r
			}
		}
		return m, nil

	case key.Matches(msg, viewKeyTop):
		m.policyTable.GotoTop()
		return m, nil
	case key.Matches(msg, viewKeyBot):
		m.policyTable.GotoBottom()
		return m, nil

	case key.Matches(msg, viewKeyEnter):
		if m.editState == policyStateMoving {
			idx := m.policyTable.Cursor()
			if idx >= 0 && idx < len(m.draftRules) {
				destRule := m.draftRules[idx]
				var sourceFile string
				var sourceRuleID int
				for _, r := range m.draftRules {
					if r.ID == m.moveSourceID {
						sourceFile = r.File
						sourceRuleID = r.ID
						break
					}
				}
				localIdx := 0
				for i, r := range m.draftRules {
					if r.File == destRule.File {
						if i == idx {
							break
						}
						localIdx++
					}
				}
				if errMsg, _ := moveRuleDraft(sourceFile, destRule.File, sourceRuleID, localIdx); errMsg != "" {
					m.setStatusErr(errMsg)
				}
			}
			m.editState = policyStateNormal
			return m, fetchDataCmd()
		}
		if r := m.selectedRule(); r != nil && r.Kind != "section" {
			m.detailRule = r
			m.modal = modalRuleDetail
			m.viewport.SetContent(m.renderRuleDetail(r))
			m.viewport.GotoTop()
		}
		return m, nil

	case key.Matches(msg, viewKeyBack):
		if m.editState == policyStateMoving {
			m.editState = policyStateNormal
			m.updateData()
		}
		return m, nil
	}
	m.policyTable, cmd = m.policyTable.Update(msg)
	return m, cmd
}

func (m cliModel) renderPolicy() string {
	if m.ruleForm.active {
		return m.renderRuleForm()
	}

	base := ""
	if m.deleteTarget != nil {
		base = m.styles.Warning.Copy().Bold(true).Render(
			fmt.Sprintf("DELETE rule #%d (%s)? y to delete, any other key to cancel", m.deleteTarget.ID, m.deleteTarget.Body)) + "\n\n"
	} else if m.editState == policyStateMoving {
		base = m.styles.Warning.Render("MOVE MODE: j/k select destination, Enter to place, Esc to cancel") + "\n\n"
	}

	if m.baseline != nil {
		input := m.baseline["input"]
		base += fmt.Sprintf("Default Policies: INPUT=%v  FORWARD=%v  OUTPUT=%v\n",
			mapVal(input, "policy"), mapVal(m.baseline["forward"], "policy"), mapVal(m.baseline["output"], "policy"))
		base += fmt.Sprintf("Established: %v  Whitelist: %v  Invalid: %v\n\n",
			mapVal(input, "established"), mapVal(input, "whitelist"), mapVal(input, "invalid"))
	}
	return base + m.policyTable.View()
}

// mapVal reads a key from a possibly-nil map without panicking.
func mapVal(m map[string]interface{}, k string) interface{} {
	if m == nil {
		return "-"
	}
	if v, ok := m[k]; ok {
		return v
	}
	return "-"
}

// renderPreview renders the commit-preview modal: validation result, the
// engine plan, and the deadman selector.
func (m cliModel) renderPreview() string {
	var b strings.Builder
	b.WriteString(m.styles.PanelTitle.Render("Deploy preview") + "\n\n")
	if m.previewLoading {
		b.WriteString(m.styles.Muted.Render("validating draft…"))
		return b.String()
	}
	if m.previewErr != "" {
		b.WriteString(m.styles.StatusErr.Render("✗ "+m.previewErr) + "\n")
		b.WriteString("\n" + m.styles.Muted.Render("esc close"))
		return b.String()
	}
	valid, _ := m.previewPayload["valid"].(bool)
	msg, _ := m.previewPayload["message"].(string)
	plan, _ := m.previewPayload["plan"].(string)
	if !valid {
		b.WriteString(m.styles.StatusErr.Render("✗ draft does not validate") + "\n\n")
		b.WriteString(msg + "\n")
		b.WriteString("\n" + m.styles.Muted.Render("esc close, fix the draft, retry"))
		return b.String()
	}
	b.WriteString(m.styles.AcceptVerdict.Render("✓ draft validates") + "\n")
	if msg != "" {
		b.WriteString(m.styles.Muted.Render(msg) + "\n")
	}
	if plan != "" {
		b.WriteString("\n" + m.styles.PanelTitle.Render("Plan") + "\n" + plan + "\n")
	}
	b.WriteString("\n" + m.styles.Warning.Render(fmt.Sprintf("deadman: %ds  (←/→ adjust)", m.previewSeconds)) + "\n")
	b.WriteString(m.styles.Muted.Render("y deploy · esc cancel"))
	return b.String()
}
