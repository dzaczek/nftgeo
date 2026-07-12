package main

import (
	"fmt"
	"os"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

var (
	tabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Border(lipgloss.NormalBorder(), false, true, false, false).
			BorderForeground(lipgloss.Color("238"))

	activeTabStyle = tabStyle.Copy().
			Foreground(lipgloss.Color("10")).
			Bold(true)

	windowStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("238")).
			Padding(1, 2)

	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	logHeaderStyle     = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("240"))
	dropVerdictStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	acceptVerdictStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
)

type cliModel struct {
	activeTab int
	tabs      []string
	width     int
	height    int

	logs []Drop

	policies     []PolicyRule
	policyCursor int

	ipInput      textinput.Model
	blacklistMsg string
}

func initialModel() cliModel {
	ti := textinput.New()
	ti.Placeholder = "Enter IP to blacklist (e.g. 192.168.1.50)"
	ti.Focus()
	ti.CharLimit = 156
	ti.Width = 40

	return cliModel{
		activeTab: 0,
		tabs:      []string{"Policy", "Logs"},
		ipInput:   ti,
	}
}

type logsMsg []Drop
type policiesMsg []PolicyRule

func fetchLogs() tea.Cmd {
	return func() tea.Msg {
		resp := drops("-24h")
		return logsMsg(resp.Recent)
	}
}

func fetchPolicies() tea.Cmd {
	return func() tea.Msg {
		return policiesMsg(policy())
	}
}

func (m cliModel) Init() tea.Cmd {
	return tea.Batch(fetchLogs(), fetchPolicies(), textinput.Blink)
}

func (m cliModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case logsMsg:
		m.logs = msg
	case policiesMsg:
		m.policies = msg
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "q":
			return m, tea.Quit
		case "tab", "l", "right":
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
		case "shift+tab", "h", "left":
			m.activeTab = (m.activeTab - 1 + len(m.tabs)) % len(m.tabs)

		case "j", "down":
			if m.activeTab == 0 && m.policyCursor < len(m.policies)-1 {
				m.policyCursor++
			}
		case "k", "up":
			if m.activeTab == 0 && m.policyCursor > 0 {
				m.policyCursor--
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
	}

	return m, nil
}

func (m cliModel) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	var renderedTabs []string
	for i, t := range m.tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, activeTabStyle.Render(t))
		} else {
			renderedTabs = append(renderedTabs, tabStyle.Render(t))
		}
	}
	row := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)

	content := ""
	switch m.activeTab {
	case 0:
		content = m.renderPolicy()
	case 1:
		content = m.renderLogs()
	}

	mainContent := windowStyle.Width(m.width - 4).Height(m.height - 5).Render(content)

	help := helpStyle.Render("tab/h/l: switch tabs • q: quit")

	return lipgloss.JoinVertical(lipgloss.Left, row, mainContent, help)
}

func (m cliModel) renderPolicy() string {
	if len(m.policies) == 0 {
		return "No policies available."
	}

	res := logHeaderStyle.Render(fmt.Sprintf("  %-6s %-6s %-6s %-6s %-12s %s", "ACTION", "DIR", "PROTO", "PORT", "TARGET", "IFACE")) + "\n"

	for i, p := range m.policies {
		cursor := " "
		style := lipgloss.NewStyle()
		if i == m.policyCursor {
			cursor = ">"
			style = style.Foreground(lipgloss.Color("10")).Bold(true)
		}

		row := fmt.Sprintf("%s %-6s %-6s %-6s %-6s %-12s %s",
			cursor,
			p.Action,
			p.Dir,
			p.Proto,
			p.Port,
			p.Target,
			p.Iface,
		)
		res += style.Render(row) + "\n"
	}

	return res
}

func (m cliModel) renderLogs() string {
	if len(m.logs) == 0 {
		return "No logs available."
	}

	header := fmt.Sprintf("%-25s %-20s %-10s %-8s %-20s %s", "TIME", "SRC", "DPORT", "PROTO", "REASON", "VERDICT")
	res := logHeaderStyle.Render(header) + "\n"

	for _, l := range m.logs {
		vStyle := dropVerdictStyle
		if l.Verdict == "accept" {
			vStyle = acceptVerdictStyle
		}

		row := fmt.Sprintf("%-25s %-20s %-10s %-8s %-20s %s",
			l.Time,
			l.Src,
			l.Dport,
			l.Proto,
			l.Reason,
			vStyle.Render(l.Verdict),
		)
		res += row + "\n"
	}
	return res
}

func startCLI(args []string) {
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error starting CLI: %v", err)
		os.Exit(1)
	}
}
