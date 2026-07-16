package main

// Objects → Reference subview: an editable whitelist (the same
// draft→validate→apply pipeline as everything else, via saveWhitelistDraft),
// plus read-only abuse feeds and nft set sizes. Toggled with 'w' from the
// Objects tree.

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

func (m cliModel) updateReferenceKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, viewKeyUp):
		if m.refSel > 0 {
			m.refSel--
		}
		return m, nil
	case key.Matches(msg, viewKeyDown):
		if m.refSel < len(m.wlEntries)-1 {
			m.refSel++
		}
		return m, nil
	case key.Matches(msg, objectsKeys.Add):
		m.refAddMode = true
		m.objInput.SetValue("")
		m.objInput.Focus()
		return m, nil
	case key.Matches(msg, objectsKeys.Delete):
		if m.refSel >= 0 && m.refSel < len(m.wlEntries) {
			m.wlEntries = append(m.wlEntries[:m.refSel], m.wlEntries[m.refSel+1:]...)
			if m.refSel > 0 && m.refSel >= len(m.wlEntries) {
				m.refSel--
			}
			m.saveWhitelist()
			return m, fetchDataCmd()
		}
		return m, nil
	}
	return m, nil
}

// updateReferenceInput owns the keyboard while adding a whitelist entry.
func (m cliModel) updateReferenceInput(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch {
	case key.Matches(msg, viewKeyBack):
		m.refAddMode = false
		return m, nil
	case key.Matches(msg, viewKeyEnter):
		val := strings.TrimSpace(m.objInput.Value())
		m.refAddMode = false
		if val == "" {
			return m, nil
		}
		m.wlEntries = append(m.wlEntries, val)
		m.saveWhitelist()
		return m, fetchDataCmd()
	}
	m.objInput, cmd = m.objInput.Update(msg)
	return m, cmd
}

// saveWhitelist stages the whitelist draft (entries edited here, hosts kept as
// loaded) through the shared saveWhitelistDraft path; validation errors are
// surfaced and the offending change stays visible for correction.
func (m *cliModel) saveWhitelist() {
	if errMsg, _ := saveWhitelistDraft(m.wlEntries, m.wlHosts); errMsg != "" {
		m.setStatusErr(errMsg)
		return
	}
	m.setStatusInfo("whitelist draft saved — c to commit")
}

func (m cliModel) renderReference() string {
	var b strings.Builder
	b.WriteString(m.styles.PanelTitle.Render("Reference — whitelist / feeds / sets") + "\n")
	b.WriteString(m.styles.Muted.Render("edits stage a draft; press c to commit through the deadman") + "\n\n")

	// Whitelist editor
	b.WriteString(m.styles.PanelTitle.Render(fmt.Sprintf("Whitelist (%d)", len(m.wlEntries))) + "\n")
	if m.refAddMode {
		b.WriteString("  " + m.styles.Accent.Render("+ ") + m.objInput.View() + "\n")
	}
	if len(m.wlEntries) == 0 && !m.refAddMode {
		b.WriteString(m.styles.Muted.Render("  (empty — press a to add an IP or CIDR)") + "\n")
	}
	for i, e := range m.wlEntries {
		cursor := "  "
		line := e
		if i == m.refSel && !m.refAddMode {
			cursor = m.styles.Accent.Render("▶ ")
			line = m.styles.Accent.Copy().Bold(true).Render(e)
		}
		b.WriteString(cursor + line + "\n")
	}
	if len(m.wlHosts) > 0 {
		b.WriteString(m.styles.Muted.Render(fmt.Sprintf("  hosts: %s", strings.Join(m.wlHosts, ", "))) + "\n")
	}

	// Two read-only columns: feeds and sets
	var feedCol strings.Builder
	feedCol.WriteString(m.styles.PanelTitle.Render("Abuse feeds") + "\n")
	if len(m.feeds) == 0 {
		feedCol.WriteString(m.styles.Muted.Render("  none"))
	}
	for _, f := range m.feeds {
		mark := m.styles.AcceptVerdict.Render("●")
		if !asBool(f, "fresh") {
			mark = m.styles.Warning.Render("●")
		}
		feedCol.WriteString(fmt.Sprintf("  %s %-14s %8s  %dh\n",
			mark, clip(asStr(f, "name"), 14), formatCount(asInt(f, "count")), asInt(f, "ageHours")))
	}

	var setCol strings.Builder
	setCol.WriteString(m.styles.PanelTitle.Render("nft sets") + "\n")
	if len(m.setsList) == 0 {
		setCol.WriteString(m.styles.Muted.Render("  none"))
	}
	for _, s := range m.setsList {
		setCol.WriteString(fmt.Sprintf("  %-18s %8s\n", clip(s.Name, 18), formatCount(s.Count)))
	}

	colW := (m.viewWidth() - 2) / 2
	if colW < 24 {
		colW = 24
	}
	cols := joinColumns(colW, feedCol.String(), setCol.String())

	b.WriteString("\n" + cols)
	return b.String()
}
