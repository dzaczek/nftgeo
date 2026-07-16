package main

// Logs view: the recent drop/accept feed with filtering and an IP lookup
// modal. Columns are responsive (recomputed on every resize).

import (
	"strings"

	"github.com/charmbracelet/bubbles/key"
	bubblesTable "github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type logsKeyMap struct {
	Filter key.Binding
	CycleV key.Binding
	CycleD key.Binding
}

var logsKeys = logsKeyMap{
	Filter: key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "search")),
	CycleV: key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "verdict")),
	CycleD: key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "direction")),
}

const logsHints = "↑↓ move · enter lookup · / search · v verdict · f dir"

var logColSpecs = []colSpec{
	{title: "Time", min: 20},
	{title: "Src", min: 15, weight: 2},
	{title: "CC", min: 3},
	{title: "Dport", min: 5},
	{title: "Proto", min: 5},
	{title: "Reason", min: 14, weight: 3},
	{title: "Verdict", min: 7},
}

func logColumns(width int) []bubblesTable.Column {
	// each bubbles table cell pads 1 left+right; reserve that per column
	return toTableColumns(logColSpecs, layoutCols(width-2*len(logColSpecs), logColSpecs))
}

func (m *cliModel) updateLogsData() {
	var rows []bubblesTable.Row
	txt := strings.ToLower(m.filterInput.Value())
	for _, d := range m.drops.Recent {
		if m.verdictFilter != "" && d.Verdict != m.verdictFilter {
			continue
		}
		if m.dirFilter != "" && d.Dir != m.dirFilter {
			continue
		}
		if txt != "" && !strings.Contains(strings.ToLower(d.Src), txt) && !strings.Contains(strings.ToLower(d.Reason), txt) {
			continue
		}

		v := d.Verdict
		if d.Verdict == "drop" {
			v = m.styles.DropVerdict.Render(v)
		} else {
			v = m.styles.AcceptVerdict.Render(v)
		}

		rows = append(rows, bubblesTable.Row{
			d.Time, d.Src, d.CC, d.Dport, d.Proto, d.Reason, v,
		})
	}
	m.logTable.SetRows(rows)
}

func (m cliModel) updateLogsKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch {
	case key.Matches(msg, logsKeys.Filter):
		m.showFilter = true
		m.filterInput.Focus()
		m.filterInput.SetValue("")
		return m, nil
	case key.Matches(msg, logsKeys.CycleV):
		switch m.verdictFilter {
		case "":
			m.verdictFilter = "drop"
		case "drop":
			m.verdictFilter = "accept"
		default:
			m.verdictFilter = ""
		}
		m.updateData()
		return m, nil
	case key.Matches(msg, logsKeys.CycleD):
		switch m.dirFilter {
		case "":
			m.dirFilter = "ingress"
		case "ingress":
			m.dirFilter = "egress"
		case "egress":
			m.dirFilter = "forward"
		default:
			m.dirFilter = ""
		}
		m.updateData()
		return m, nil
	case key.Matches(msg, viewKeyTop):
		m.logTable.GotoTop()
		return m, nil
	case key.Matches(msg, viewKeyBot):
		m.logTable.GotoBottom()
		return m, nil
	case key.Matches(msg, viewKeyEnter):
		if len(m.logTable.Rows()) > 0 {
			row := m.logTable.SelectedRow()
			if len(row) > 1 {
				return m, lookupCmd(row[1])
			}
		}
		return m, nil
	}
	m.logTable, cmd = m.logTable.Update(msg)
	return m, cmd
}

func (m cliModel) renderLogs() string {
	filterInfo := "Filters: "
	if m.verdictFilter != "" {
		filterInfo += "Verdict=" + strings.ToUpper(m.verdictFilter) + " "
	} else {
		filterInfo += "Verdict=ALL "
	}
	if m.dirFilter != "" {
		filterInfo += "Dir=" + strings.ToUpper(m.dirFilter) + " "
	} else {
		filterInfo += "Dir=ALL "
	}
	if m.filterInput.Value() != "" {
		filterInfo += "Search='" + m.filterInput.Value() + "'"
	}

	fLine := m.styles.Muted.Render(filterInfo)
	if m.showFilter {
		fLine = lipgloss.JoinHorizontal(lipgloss.Top,
			m.styles.Accent.Copy().Bold(true).Render("FIND: "),
			m.filterInput.View(),
		)
	}

	return lipgloss.JoinVertical(lipgloss.Left, fLine, "", m.logTable.View())
}

func (m cliModel) renderLookupDetails() string {
	if m.lookupRes == nil {
		return "Loading..."
	}
	ip := asStr(m.lookupRes, "ip")
	res := "Lookup for: " + m.styles.Accent.Copy().Bold(true).Render(ip) + "\n\n"

	if ptr, ok := m.lookupRes["ptr"].([]string); ok {
		res += m.styles.Accent.Copy().Bold(true).Render("Reverse DNS:") + "\n"
		for _, n := range ptr {
			res += "  " + n + "\n"
		}
		res += "\n"
	}

	if rdap, ok := m.lookupRes["rdap"].(map[string]interface{}); ok {
		res += m.styles.Accent.Copy().Bold(true).Render("RDAP Information:") + "\n"
		res += "  Org:     " + asStr(rdap, "org") + "\n"
		res += "  CIDR:    " + asStr(rdap, "cidr") + "\n"
		res += "  Country: " + asStr(rdap, "country") + "\n"
		res += "  Handle:  " + asStr(rdap, "handle") + "\n"
	}

	res += "\n\nPress ESC to close"
	return res
}
