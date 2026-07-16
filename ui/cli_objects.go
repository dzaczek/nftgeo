package main

// Objects view: a 3-level tree (Category → Entry → Member) over the objects
// draft. Navigation is Enter to descend and Esc to ascend — deliberately NOT
// h/l/arrows, which belong to nothing (tab switching is tab/shift+tab/1-5),
// so the old collision that made this tab uneditable cannot come back.
// Every save goes through writeObjectsDraft, the same path as the web PUT.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type objectsKeyMap struct {
	Add    key.Binding
	Edit   key.Binding
	Delete key.Binding
}

var objectsKeys = objectsKeyMap{
	Add:    key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "add")),
	Edit:   key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "edit")),
	Delete: key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "delete")),
}

const objectsHints = "↑↓ move · enter open · esc up · a add · e edit · d delete · w reference"
const referenceHints = "↑↓ move · a add · d delete · w back to tree"

var objCategories = []string{"Groups", "Regions", "Services", "Hosts", "Zones", "Lists", "Feeds"}

// refKey toggles between the object tree and the Reference subview.
var refKey = key.NewBinding(key.WithKeys("w"), key.WithHelp("w", "reference"))

func (m cliModel) updateObjectsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	if key.Matches(msg, refKey) {
		m.objRef = !m.objRef
		m.refSel = 0
		return m, nil
	}
	if m.objRef {
		return m.updateReferenceKeys(msg)
	}
	switch {
	case key.Matches(msg, viewKeyEnter):
		// descend: Category -> Entry -> Member
		switch m.objLevel {
		case 0:
			if len(m.objDrafts) > m.objSelectedCategory && len(m.objDrafts[m.objSelectedCategory]) > 0 {
				m.objLevel = 1
				m.objSelectedEntry = 0
				m.objSelectedMember = 0
			} else {
				m.setStatusInfo("no entries — press a to add one")
				m.objLevel = 1
			}
		case 1:
			entries := m.objEntries()
			if m.objSelectedEntry >= 0 && m.objSelectedEntry < len(entries) {
				m.objLevel = 2
				m.objSelectedMember = 0
			}
		}
		return m, nil

	case key.Matches(msg, viewKeyBack):
		if m.objLevel > 0 {
			m.objLevel--
		}
		return m, nil

	case key.Matches(msg, viewKeyUp):
		switch m.objLevel {
		case 0:
			if m.objSelectedCategory > 0 {
				m.objSelectedCategory--
				m.objSelectedEntry = 0
				m.objSelectedMember = 0
			}
		case 1:
			if m.objSelectedEntry > 0 {
				m.objSelectedEntry--
				m.objSelectedMember = 0
			}
		case 2:
			if m.objSelectedMember > 0 {
				m.objSelectedMember--
			}
		}
		return m, nil

	case key.Matches(msg, viewKeyDown):
		switch m.objLevel {
		case 0:
			if m.objSelectedCategory < len(objCategories)-1 {
				m.objSelectedCategory++
				m.objSelectedEntry = 0
				m.objSelectedMember = 0
			}
		case 1:
			if m.objSelectedEntry < len(m.objEntries())-1 {
				m.objSelectedEntry++
				m.objSelectedMember = 0
			}
		case 2:
			entries := m.objEntries()
			if m.objSelectedEntry >= 0 && m.objSelectedEntry < len(entries) &&
				m.objSelectedMember < len(entries[m.objSelectedEntry].Members)-1 {
				m.objSelectedMember++
			}
		}
		return m, nil

	case key.Matches(msg, objectsKeys.Add):
		if m.objLevel > 0 {
			m.objInputMode = true
			if m.objLevel == 1 {
				m.objInputContext = "entry_name"
			} else {
				m.objInputContext = "member_value"
			}
			m.objInput.SetValue("")
			m.objInput.Focus()
		} else {
			m.setStatusInfo("open a category first (enter)")
		}
		return m, nil

	case key.Matches(msg, objectsKeys.Edit):
		if m.objLevel > 0 {
			entries := m.objEntries()
			if len(entries) == 0 {
				return m, nil
			}
			m.objInputMode = true
			if m.objLevel == 1 {
				m.objInputContext = "edit_entry"
				if m.objSelectedEntry >= 0 && m.objSelectedEntry < len(entries) {
					m.objInput.SetValue(entries[m.objSelectedEntry].Name)
				}
			} else {
				m.objInputContext = "edit_member"
				if m.objSelectedEntry >= 0 && m.objSelectedEntry < len(entries) {
					members := entries[m.objSelectedEntry].Members
					if m.objSelectedMember >= 0 && m.objSelectedMember < len(members) {
						m.objInput.SetValue(members[m.objSelectedMember])
					}
				}
			}
			m.objInput.Focus()
		}
		return m, nil

	case key.Matches(msg, objectsKeys.Delete):
		if m.objLevel > 0 {
			m.handleObjDelete()
			return m, fetchDataCmd()
		}
		return m, nil
	}
	return m, nil
}

// updateObjectsInput owns the keyboard while the add/edit text input is open.
func (m cliModel) updateObjectsInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch {
	case key.Matches(msg, viewKeyEnter):
		m.handleObjInputEnter()
		return m, fetchDataCmd()
	case key.Matches(msg, viewKeyBack):
		m.objInputMode = false
		return m, nil
	}
	m.objInput, cmd = m.objInput.Update(msg)
	return m, cmd
}

// objEntries returns the selected category's entries (nil-safe).
func (m *cliModel) objEntries() []objEntry {
	if m.objSelectedCategory < 0 || m.objSelectedCategory >= len(m.objDrafts) {
		return nil
	}
	return m.objDrafts[m.objSelectedCategory]
}

func (m *cliModel) handleObjInputEnter() {
	val := m.objInput.Value()
	if val == "" {
		return
	}

	if m.objSelectedCategory < 0 || m.objSelectedCategory >= len(m.objDrafts) {
		return
	}

	entries := make([]objEntry, len(m.objDrafts[m.objSelectedCategory]))
	copy(entries, m.objDrafts[m.objSelectedCategory])

	switch m.objInputContext {
	case "entry_name":
		for _, e := range entries {
			if e.Name == val {
				m.setStatusErr("entry " + val + " already exists")
				return
			}
		}
		entries = append(entries, objEntry{Name: val, Members: []string{}})
		m.objDrafts[m.objSelectedCategory] = entries
	case "member_value":
		if m.objSelectedEntry >= len(entries) {
			return
		}
		entries[m.objSelectedEntry].Members = append(entries[m.objSelectedEntry].Members, val)
		m.objDrafts[m.objSelectedCategory] = entries
	case "edit_entry":
		if m.objSelectedEntry >= len(entries) {
			return
		}
		for i, e := range entries {
			if i != m.objSelectedEntry && e.Name == val {
				m.setStatusErr("entry " + val + " already exists")
				return
			}
		}
		entries[m.objSelectedEntry].Name = val
		m.objDrafts[m.objSelectedCategory] = entries
	case "edit_member":
		if m.objSelectedEntry >= len(entries) {
			return
		}
		members := entries[m.objSelectedEntry].Members
		if m.objSelectedMember >= len(members) {
			return
		}
		entries[m.objSelectedEntry].Members[m.objSelectedMember] = val
		m.objDrafts[m.objSelectedCategory] = entries
	}

	m.saveObjectsDraft()
	m.objInputMode = false
}

func (m *cliModel) handleObjDelete() {
	if m.objSelectedCategory < 0 || m.objSelectedCategory >= len(m.objDrafts) {
		return
	}

	entries := make([]objEntry, len(m.objDrafts[m.objSelectedCategory]))
	copy(entries, m.objDrafts[m.objSelectedCategory])

	if m.objLevel == 1 { // Delete entry
		if m.objSelectedEntry >= len(entries) {
			return
		}
		entries = append(entries[:m.objSelectedEntry], entries[m.objSelectedEntry+1:]...)
		m.objDrafts[m.objSelectedCategory] = entries
		if m.objSelectedEntry > 0 {
			m.objSelectedEntry--
		}
	} else if m.objLevel == 2 { // Delete member
		if m.objSelectedEntry >= len(entries) {
			return
		}
		members := entries[m.objSelectedEntry].Members
		if m.objSelectedMember >= len(members) {
			return
		}
		members = append(members[:m.objSelectedMember], members[m.objSelectedMember+1:]...)
		entries[m.objSelectedEntry].Members = members
		m.objDrafts[m.objSelectedCategory] = entries
		if m.objSelectedMember > 0 {
			m.objSelectedMember--
		}
	}

	m.saveObjectsDraft()
}

// saveObjectsDraft stages the edited object set through the same
// writeObjectsDraft path the web PUT handler uses.
func (m *cliModel) saveObjectsDraft() {
	if len(m.objDrafts) < 7 {
		return
	}
	_, errMsg, _ := writeObjectsDraft(m.objDrafts[0], m.objDrafts[1], m.objDrafts[2], m.objDrafts[3], m.objDrafts[4], m.objDrafts[5], m.objDrafts[6])
	if errMsg != "" {
		m.setStatusErr("invalid object: " + errMsg)
		return
	}
	m.objHasDraft = true
	m.setStatusInfo("objects draft saved — c to commit")
}

func (m cliModel) renderObjects() string {
	if m.objRef {
		return m.renderReference()
	}
	if m.objDrafts == nil {
		return "Loading..."
	}

	var sb strings.Builder

	if m.objHasDraft {
		sb.WriteString(m.styles.Warning.Render("* unsaved draft — press c to commit") + "\n\n")
	} else {
		sb.WriteString("\n\n")
	}

	colWidth := (m.width - 10) / 3
	if colWidth < 20 {
		colWidth = 20
	}

	styleNormal := lipgloss.NewStyle().Width(colWidth).Padding(0, 1)
	styleSelected := lipgloss.NewStyle().Width(colWidth).Padding(0, 1).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("14"))
	styleParent := lipgloss.NewStyle().Width(colWidth).Padding(0, 1).Foreground(lipgloss.Color("14")).Bold(true)
	styleDimmed := lipgloss.NewStyle().Width(colWidth).Padding(0, 1).Foreground(lipgloss.Color("240"))

	var catView strings.Builder
	for i, c := range objCategories {
		label := c
		if i < len(m.objDrafts) {
			label = fmt.Sprintf("%s (%d)", c, len(m.objDrafts[i]))
		}
		s := styleNormal
		if m.objLevel == 0 && i == m.objSelectedCategory {
			s = styleSelected
		} else if i == m.objSelectedCategory {
			s = styleParent
		} else if m.objLevel > 0 {
			s = styleDimmed
		}
		catView.WriteString(s.Render(label) + "\n")
	}

	var entView strings.Builder
	var memView strings.Builder

	entries := m.objEntries()
	if entries != nil {
		if m.objInputMode && m.objLevel == 1 {
			entView.WriteString(styleSelected.Render("> "+m.objInput.View()) + "\n")
		}

		for i, e := range entries {
			label := fmt.Sprintf("%s (%d)", e.Name, len(e.Members))
			s := styleNormal
			if m.objLevel == 1 && i == m.objSelectedEntry && !m.objInputMode {
				s = styleSelected
			} else if i == m.objSelectedEntry && m.objLevel > 1 {
				s = styleParent
			} else if m.objLevel != 1 {
				s = styleDimmed
			}
			entView.WriteString(s.Render(label) + "\n")
		}

		if m.objSelectedEntry >= 0 && m.objSelectedEntry < len(entries) {
			members := entries[m.objSelectedEntry].Members
			if m.objInputMode && m.objLevel == 2 {
				memView.WriteString(styleSelected.Render("> "+m.objInput.View()) + "\n")
			}
			for i, mval := range members {
				s := styleNormal
				if m.objLevel == 2 && i == m.objSelectedMember && !m.objInputMode {
					s = styleSelected
				} else if m.objLevel < 2 {
					s = styleDimmed
				}
				memView.WriteString(s.Render(mval) + "\n")
			}
		}
	}

	headerStyle := lipgloss.NewStyle().Width(colWidth).Bold(true).Underline(true).Padding(0, 1)

	row1 := lipgloss.JoinHorizontal(lipgloss.Top,
		headerStyle.Render("Category"),
		headerStyle.Render("Entry"),
		headerStyle.Render("Member"),
	)

	row2 := lipgloss.JoinHorizontal(lipgloss.Top,
		catView.String(),
		entView.String(),
		memView.String(),
	)

	sb.WriteString(row1 + "\n")
	sb.WriteString(row2)

	return sb.String()
}
