package main

// Logs view: the recent drop/accept feed with full connection details.
// Columns are responsive; Enter opens a detail pane with the complete record
// plus an async PTR/RDAP lookup of the source address.

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

const logsHints = "↑↓ move · enter details · / search · v verdict · f dir"

var logColSpecs = []colSpec{
	{title: "Time", min: 20},
	{title: "Dir", min: 7},
	{title: "Src → Dst", min: 23, weight: 4},
	{title: "Port", min: 5},
	{title: "Proto", min: 5},
	{title: "CC", min: 3},
	{title: "Reason", min: 12, weight: 2},
	{title: "Verdict", min: 7},
}

func logColumns(width int) []bubblesTable.Column {
	// each bubbles table cell pads 1 left+right; reserve that per column
	return toTableColumns(logColSpecs, layoutCols(width-2*len(logColSpecs), logColSpecs))
}

// logMatches applies the active verdict/direction/text filters to one record.
// The text filter searches source, destination, reason, port and country.
func (m *cliModel) logMatches(d Drop, txt string) bool {
	if m.verdictFilter != "" && d.Verdict != m.verdictFilter {
		return false
	}
	if m.dirFilter != "" && d.Dir != m.dirFilter {
		return false
	}
	if txt == "" {
		return true
	}
	return strings.Contains(strings.ToLower(d.Src), txt) ||
		strings.Contains(strings.ToLower(d.Dst), txt) ||
		strings.Contains(strings.ToLower(d.Reason), txt) ||
		strings.Contains(strings.ToLower(d.CC), txt) ||
		strings.Contains(d.Dport, txt)
}

func (m *cliModel) updateLogsData() {
	var rows []bubblesTable.Row
	m.logFiltered = m.logFiltered[:0]
	txt := strings.ToLower(m.filterInput.Value())
	for _, d := range m.drops.Recent {
		if !m.logMatches(d, txt) {
			continue
		}

		v := d.Verdict
		if d.Verdict == "drop" {
			v = m.styles.DropVerdict.Render(v)
		} else {
			v = m.styles.AcceptVerdict.Render(v)
		}

		srcDst := d.Src
		if d.Dst != "" {
			srcDst += " → " + d.Dst
		}

		m.logFiltered = append(m.logFiltered, d)
		rows = append(rows, bubblesTable.Row{
			d.Time, d.Dir, srcDst, d.Dport, d.Proto, d.CC, d.Reason, v,
		})
	}
	m.logTable.SetRows(rows)
	// bubbles table can leave the cursor at -1 after an empty result set or
	// beyond the end after shrinking — clamp it back into range.
	if c := m.logTable.Cursor(); len(rows) > 0 && (c < 0 || c >= len(rows)) {
		if c < 0 {
			m.logTable.SetCursor(0)
		} else {
			m.logTable.SetCursor(len(rows) - 1)
		}
	}
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
		idx := m.logTable.Cursor()
		if idx >= 0 && idx < len(m.logFiltered) {
			d := m.logFiltered[idx]
			m.detailDrop = &d
			m.lookupRes = nil // fills in when the async lookup answers
			m.showLookup = true
			m.viewport.SetContent(m.renderLookupDetails())
			m.viewport.GotoTop()
			return m, lookupCmd(d.Src)
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

// renderLookupDetails renders the detail modal: the full drop record (when a
// row was selected) followed by the PTR/RDAP lookup, which streams in async.
func (m cliModel) renderLookupDetails() string {
	title := m.styles.Accent.Copy().Bold(true)
	label := m.styles.Muted
	var b strings.Builder

	if d := m.detailDrop; d != nil {
		verdict := d.Verdict
		if verdict == "drop" {
			verdict = m.styles.DropVerdict.Render(verdict)
		} else {
			verdict = m.styles.AcceptVerdict.Render(verdict)
		}
		b.WriteString(title.Render("Connection record") + "\n")
		b.WriteString(label.Render("  Time:     ") + d.Time + "\n")
		b.WriteString(label.Render("  Verdict:  ") + verdict + "\n")
		b.WriteString(label.Render("  Reason:   ") + d.Reason + "\n")
		b.WriteString(label.Render("  Dir:      ") + d.Dir + "\n")
		b.WriteString(label.Render("  Source:   ") + d.Src + "\n")
		dst := d.Dst
		if d.Dport != "" {
			dst += ":" + d.Dport
		}
		b.WriteString(label.Render("  Dest:     ") + dst + "\n")
		b.WriteString(label.Render("  Proto:    ") + d.Proto + "\n")
		b.WriteString(label.Render("  Country:  ") + d.CC + "\n\n")
	}

	if m.lookupRes == nil {
		b.WriteString(m.styles.Muted.Render("querying PTR / RDAP…") + "\n")
	} else {
		ip := asStr(m.lookupRes, "ip")
		b.WriteString(title.Render("Lookup: "+ip) + "\n")
		if ptr, ok := m.lookupRes["ptr"].([]string); ok && len(ptr) > 0 {
			b.WriteString(label.Render("  Reverse DNS: "))
			b.WriteString(strings.Join(ptr, ", ") + "\n")
		}
		if rdap, ok := m.lookupRes["rdap"].(map[string]interface{}); ok {
			b.WriteString(label.Render("  Org:     ") + asStr(rdap, "org") + "\n")
			b.WriteString(label.Render("  CIDR:    ") + asStr(rdap, "cidr") + "\n")
			b.WriteString(label.Render("  Country: ") + asStr(rdap, "country") + "\n")
			b.WriteString(label.Render("  Handle:  ") + asStr(rdap, "handle") + "\n")
		}
	}

	b.WriteString("\n" + m.styles.Muted.Render("esc close"))
	return b.String()
}
