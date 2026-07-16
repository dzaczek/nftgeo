package main

// Policy view: the draft rules table with toggle / move / add-deny and the
// baseline header. All mutations go through the shared draft functions
// (toggleRuleDraft/moveRuleDraft/cliAddDenyRule) — the same code the web
// handlers call.

import (
	"fmt"
	"net"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	bubblesTable "github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type policyKeyMap struct {
	Toggle key.Binding
	Move   key.Binding
	Add    key.Binding
}

var policyKeys = policyKeyMap{
	Toggle: key.NewBinding(key.WithKeys(" "), key.WithHelp("space", "enable/disable")),
	Move:   key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "move")),
	Add:    key.NewBinding(key.WithKeys("a", "i"), key.WithHelp("a", "add deny")),
}

const policyHints = "space toggle · m move · a add deny · r discard"

var policyColSpecs = []colSpec{
	{title: "#", min: 4},
	{title: "Action", min: 8},
	{title: "Dir", min: 5},
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
				"", "", "", "", "", "## " + r.Title, "", "", "",
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
			if r.Action == "deny" || r.Action == "drop" {
				bar = m.styles.DropVerdict.Render(bar)
			} else {
				bar = m.styles.AcceptVerdict.Render(bar)
			}
		}

		row := bubblesTable.Row{
			fmt.Sprintf("%d", r.ID), r.Action, r.Dir, r.Proto, r.Port, r.Target, r.Iface, hits, bar,
		}
		if r.Disabled || !r.Matched {
			for j, val := range row {
				row[j] = m.styles.Muted.Render(val)
			}
		}
		if r.Disabled {
			row[1] = m.styles.Muted.Render(r.Action + " (disabled)")
		}
		if m.editState == policyStateMoving && m.moveSourceID == r.ID {
			for j, val := range row {
				row[j] = m.styles.Highlight.Render(val)
			}
		}
		pRows = append(pRows, row)
	}
	m.policyTable.SetRows(pRows)
}

func (m cliModel) updatePolicyKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch {
	case key.Matches(msg, policyKeys.Toggle):
		if len(m.draftRules) > 0 && m.editState == policyStateNormal {
			idx := m.policyTable.Cursor()
			if idx >= 0 && idx < len(m.draftRules) {
				rule := m.draftRules[idx]
				if rule.Kind != "section" {
					if _, errMsg, _ := toggleRuleDraft(rule.File, rule.ID); errMsg != "" {
						m.setStatusErr(errMsg)
					}
					return m, fetchDataCmd()
				}
			}
		}
		return m, nil

	case key.Matches(msg, policyKeys.Move):
		if len(m.draftRules) > 0 && m.editState == policyStateNormal {
			idx := m.policyTable.Cursor()
			if idx >= 0 && idx < len(m.draftRules) {
				m.editState = policyStateMoving
				m.moveSourceID = m.draftRules[idx].ID
				m.updateData() // highlight row immediately
			}
		}
		return m, nil

	case key.Matches(msg, policyKeys.Add):
		if m.editState == policyStateNormal {
			m.editState = policyStatePrompt
			m.filterInput.Focus()
			m.filterInput.SetValue("")
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

// updatePolicyPrompt owns the keyboard while the add-deny prompt is open.
func (m cliModel) updatePolicyPrompt(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch {
	case key.Matches(msg, viewKeyBack):
		m.editState = policyStateNormal
		m.filterInput.Blur()
		return m, nil
	case key.Matches(msg, viewKeyEnter):
		m.editState = policyStateNormal
		m.filterInput.Blur()
		val := strings.TrimSpace(m.filterInput.Value())
		if val == "" {
			return m, nil
		}
		if net.ParseIP(val) == nil {
			if _, _, err := net.ParseCIDR(val); err != nil {
				m.setStatusErr("Invalid IP or CIDR: " + val)
				return m, nil
			}
		}
		file := "rules.conf"
		if len(m.draftRules) > 0 {
			idx := m.policyTable.Cursor()
			if idx >= 0 && idx < len(m.draftRules) {
				file = m.draftRules[idx].File
			}
		}
		if err := cliAddDenyRule(file, val); err != nil {
			m.setStatusErr(err.Error())
		} else {
			m.setStatusInfo("deny rule drafted — c to commit")
		}
		return m, fetchDataCmd()
	}
	m.filterInput, cmd = m.filterInput.Update(msg)
	return m, cmd
}

func (m cliModel) renderPolicy() string {
	base := ""
	if m.editState == policyStateMoving {
		base = m.styles.Warning.Render("MOVE MODE: j/k select destination, Enter to place, Esc to cancel") + "\n\n"
	} else if m.editState == policyStatePrompt {
		base = lipgloss.JoinHorizontal(lipgloss.Top,
			m.styles.Warning.Copy().Bold(true).Render("ADD DENY RULE (Enter target/IP): "),
			m.filterInput.View(),
		) + "\n\n"
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
