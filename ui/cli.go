package main

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/NimbleMarkets/ntcharts/barchart"
	"github.com/NimbleMarkets/ntcharts/canvas"
	"github.com/NimbleMarkets/ntcharts/linechart"
	"github.com/NimbleMarkets/ntcharts/sparkline"
	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	bubblesTable "github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

// ---- styles ----

var (
	cliHeaderStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("7")).
			Background(lipgloss.Color("24")).
			Padding(0, 1)

	cliTabStyle = lipgloss.NewStyle().
			Padding(0, 2).
			Border(lipgloss.NormalBorder(), false, true, false, false).
			BorderForeground(lipgloss.Color("238"))

	cliActiveTabStyle = cliTabStyle.Copy().
				Foreground(lipgloss.Color("10")).
				Bold(true)

	cliWindowStyle = lipgloss.NewStyle().
			Border(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("238")).
			Padding(1, 2)

	cliKpiStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("238")).
			Padding(0, 1).
			MarginRight(1)

	cliKpiLabelStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))
	cliKpiValueStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("10"))

	cliTableHeaderStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.NormalBorder()).
				BorderForeground(lipgloss.Color("240")).
				BorderBottom(true).
				Bold(true)

	cliTableSelectedStyle = lipgloss.NewStyle().
				Background(lipgloss.Color("236")).
				Foreground(lipgloss.Color("231"))

	cliHelpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	cliModalStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("12")).
			Padding(1, 2).
			Background(lipgloss.Color("234"))

	cliDropVerdictStyle   = lipgloss.NewStyle().Foreground(lipgloss.Color("9"))
	cliAcceptVerdictStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	cliMutedStyle         = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
)

// ---- keys ----

type cliKeyMap struct {
	TabNext  key.Binding
	TabPrev  key.Binding
	Up       key.Binding
	Down     key.Binding
	Jump1    key.Binding
	Jump2    key.Binding
	Jump3    key.Binding
	Jump4    key.Binding
	Jump5    key.Binding
	Help     key.Binding
	Quit     key.Binding
	Enter    key.Binding
	Back     key.Binding
	Top      key.Binding
	Bottom   key.Binding
	Filter   key.Binding
	CycleV   key.Binding
	CycleD   key.Binding
	Toggle   key.Binding
	Move     key.Binding
	Add      key.Binding
	Commit   key.Binding
	Rollback key.Binding
	ConfirmY key.Binding
	ConfirmN key.Binding
	Delete   key.Binding
	Edit     key.Binding
	Drop     key.Binding
	Reject   key.Binding
	Left     key.Binding
	Right    key.Binding
}

func (k cliKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit}
}

func (k cliKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Up, k.Down, k.TabNext, k.TabPrev},
		{k.Jump1, k.Jump2, k.Jump3, k.Jump4, k.Jump5},
		{k.Top, k.Bottom, k.Enter, k.Back},
		{k.Filter, k.CycleV, k.CycleD, k.Help, k.Quit},
	}
}

var cliKeys = cliKeyMap{
	TabNext:  key.NewBinding(key.WithKeys("tab", "l", "right"), key.WithHelp("tab/l", "next tab")),
	TabPrev:  key.NewBinding(key.WithKeys("shift+tab", "h", "left"), key.WithHelp("shift+tab/h", "prev tab")),
	Up:       key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:     key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Jump1:    key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "dashboard")),
	Jump2:    key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "logs")),
	Jump3:    key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "policy")),
	Jump4:    key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "objects")),
	Jump5:    key.NewBinding(key.WithKeys("5"), key.WithHelp("5", "system")),
	Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "toggle help")),
	Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Enter:    key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select/lookup")),
	Back:     key.NewBinding(key.WithKeys("esc", "backspace"), key.WithHelp("esc", "back")),
	Top:      key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top")),
	Bottom:   key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom")),
	Filter:   key.NewBinding(key.WithKeys("/"), key.WithHelp("/", "filter text")),
	CycleV:   key.NewBinding(key.WithKeys("v"), key.WithHelp("v", "cycle verdict")),
	CycleD:   key.NewBinding(key.WithKeys("d"), key.WithHelp("d", "cycle direction")),
	Toggle:   key.NewBinding(key.WithKeys(" ", "t"), key.WithHelp("space/t", "toggle rule")),
	Move:     key.NewBinding(key.WithKeys("m"), key.WithHelp("m", "move rule")),
	Add:      key.NewBinding(key.WithKeys("a", "i"), key.WithHelp("a/i", "add deny rule")),
	Commit:   key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "commit changes")),
	Rollback: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "rollback/discard")),
	ConfirmY: key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "confirm yes")),
	ConfirmN: key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "confirm no")),

	Delete: key.NewBinding(key.WithKeys("d", "delete"), key.WithHelp("d", "delete")),
	Edit:   key.NewBinding(key.WithKeys("e", "enter"), key.WithHelp("e/enter", "edit")),
	Drop:   key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "drop/no")),
	Reject: key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "reject/rollback")),
	Left:   key.NewBinding(key.WithKeys("left", "h"), key.WithHelp("left/h", "move left")),
	Right:  key.NewBinding(key.WithKeys("right", "l"), key.WithHelp("right/l", "move right")),
}

// ---- model ----

type policyEditState int

const (
	policyStateNormal policyEditState = iota
	policyStateMoving
	policyStatePrompt
	policyStateConfirming
)

type cliModel struct {
	activeTab int
	tabs      []string
	width     int
	height    int

	// data
	draftRules  []*draftRule
	status      map[string]interface{}
	drops       DropsResp
	policies    []PolicyRule
	baseline    map[string]map[string]interface{}
	objects     map[string]interface{}
	ifStats     map[string]interface{}
	lookupRes   map[string]interface{}
	objDrafts   [][]objEntry
	objHasDraft bool

	// components
	logTable    bubblesTable.Model
	policyTable bubblesTable.Model
	viewport    viewport.Model // for lookup details
	help        help.Model
	filterInput textinput.Model

	// filters
	verdictFilter string // "", "drop", "accept"
	dirFilter     string // "", "ingress", "egress", "forward"

	// charts
	dropsChart    linechart.Model
	ingressChart  barchart.Model
	topPortsChart barchart.Model
	rxSparklines  map[string]sparkline.Model
	txSparklines  map[string]sparkline.Model

	showHelp   bool
	showLookup bool
	showFilter bool
	loading    bool
	lastFetch  time.Time

	// policy edit state
	editState        policyEditState
	moveSourceID     int
	confirmRemaining int

	// objects edit state
	objLevel            int
	objSelectedCategory int
	objSelectedEntry    int
	objSelectedMember   int
	objInputMode        bool
	objInputContext     string
	objInput            textinput.Model
}

func initialModel() cliModel {
	ti := textinput.New()
	ti.Placeholder = "Filter..."
	ti.CharLimit = 64
	ti.Width = 30

	m := cliModel{
		activeTab:    0,
		tabs:         []string{"Dashboard", "Logs", "Policy", "Objects", "System"},
		rxSparklines: make(map[string]sparkline.Model),
		txSparklines: make(map[string]sparkline.Model),
		help:         help.New(),
		filterInput:  ti,
		loading:      true,

		objLevel:            0,
		objSelectedCategory: 0,
		objInput:            textinput.New(),
	}

	// Initialize tables
	columns := []bubblesTable.Column{
		{Title: "Time", Width: 20},
		{Title: "Src", Width: 16},
		{Title: "CC", Width: 4},
		{Title: "Dport", Width: 6},
		{Title: "Proto", Width: 6},
		{Title: "Reason", Width: 15},
		{Title: "Verdict", Width: 8},
	}
	m.logTable = bubblesTable.New(
		bubblesTable.WithColumns(columns),
		bubblesTable.WithFocused(true),
	)
	s := bubblesTable.DefaultStyles()
	s.Header = cliTableHeaderStyle
	s.Selected = cliTableSelectedStyle
	m.logTable.SetStyles(s)

	pColumns := []bubblesTable.Column{
		{Title: "#", Width: 4},
		{Title: "Action", Width: 8},
		{Title: "Dir", Width: 6},
		{Title: "Proto", Width: 6},
		{Title: "Port", Width: 10},
		{Title: "Target", Width: 15},
		{Title: "Iface", Width: 8},
		{Title: "Hits", Width: 10},
		{Title: "Activity", Width: 12},
	}
	m.policyTable = bubblesTable.New(
		bubblesTable.WithColumns(pColumns),
		bubblesTable.WithFocused(true),
	)
	m.policyTable.SetStyles(s)

	// Charts
	m.dropsChart = linechart.New(80, 10, 0, 23, 0, 100)
	m.ingressChart = barchart.New(40, 10)
	m.ingressChart.SetHorizontal(true)
	m.ingressChart.SetShowAxis(true)
	m.topPortsChart = barchart.New(40, 10)
	m.topPortsChart.SetShowAxis(true)

	m.viewport = viewport.New(60, 20)

	return m
}

// ---- commands ----

type tickMsg time.Time
type fetchMsg struct {
	status      map[string]interface{}
	drafts      []*draftRule
	drops       DropsResp
	policies    []PolicyRule
	baseline    map[string]map[string]interface{}
	objects     map[string]interface{}
	ifStats     map[string]interface{}
	objDrafts   [][]objEntry
	objHasDraft bool
}
type lookupMsg map[string]interface{}

func tickCmd() tea.Cmd {
	return tea.Tick(5*time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

func fetchDataCmd() tea.Cmd {
	return func() tea.Msg {
		ch := chains()
		st := map[string]interface{}{
			"version": version(),
			"loaded":  tableLoaded(),
			"chains":  ch,
			"health":  health(ch),
			"time":    time.Now().UTC().Format(time.RFC3339),
		}
		dr := drops("-24h")
		pl := policy()
		annotate(pl, ruleCounters())

		bc := baselineCounters()
		pol := chainPolicies()
		bs := map[string]map[string]interface{}{}
		for hook, ctr := range bc {
			m := map[string]interface{}{}
			for k, v := range ctr {
				m[k] = v
			}
			bs[hook] = m
		}
		for hook, p := range pol {
			if bs[hook] == nil {
				bs[hook] = map[string]interface{}{}
			}
			bs[hook]["policy"] = p
		}

		text := readFileStr(objLiveFile)
		_, err := os.Stat(objDraftFile)
		hasDraft := err == nil
		if hasDraft {
			text = readFileStr(objDraftFile)
		}
		g, rg, sv, hs, zn, ls, fd := parseObjects(text)
		objDrafts := [][]objEntry{g, rg, sv, hs, zn, ls, fd}

		return fetchMsg{
			status:      st,
			drafts:      cliDraftRules(),
			drops:       dr,
			policies:    pl,
			baseline:    bs,
			objects:     objects(),
			ifStats:     ifStats(),
			objDrafts:   objDrafts,
			objHasDraft: hasDraft,
		}
	}
}

func lookupCmd(ip string) tea.Cmd {
	return func() tea.Msg {
		return lookupMsg(doLookup(ip))
	}
}

// ---- update ----

func (m cliModel) Init() tea.Cmd {
	return tea.Batch(fetchDataCmd(), tickCmd())
}

func (m cliModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tickMsg:
		if m.editState == policyStateConfirming {
			m.confirmRemaining--
			if m.confirmRemaining <= 0 {
				run(nftgeoBin, "rollback")
				restoreBackups()
				m.editState = policyStateNormal
			}
		}
		return m, tea.Batch(fetchDataCmd(), tickCmd())

	case fetchMsg:
		if err, ok := m.status["commitError"].(string); ok && err != "" {
			msg.status["commitError"] = err
		}
		m.status = msg.status
		m.draftRules = msg.drafts
		m.drops = msg.drops
		m.policies = msg.policies
		m.baseline = msg.baseline
		m.objects = msg.objects
		m.ifStats = msg.ifStats
		m.objDrafts = msg.objDrafts
		m.objHasDraft = msg.objHasDraft
		m.loading = false
		m.lastFetch = time.Now()
		m.updateData()

	case lookupMsg:
		m.lookupRes = msg
		m.showLookup = true
		m.viewport.SetContent(m.renderLookupDetails())

	case tea.KeyMsg:
		if m.showLookup {
			switch {
			case key.Matches(msg, cliKeys.Back), key.Matches(msg, cliKeys.Quit):
				m.showLookup = false
				return m, nil
			}
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}

		if m.activeTab == 3 && m.objInputMode {
			switch {
			case key.Matches(msg, cliKeys.Enter):
				m.handleObjInputEnter()
				return m, fetchDataCmd()
			case key.Matches(msg, cliKeys.Back), key.Matches(msg, cliKeys.Quit):
				m.objInputMode = false
				return m, nil
			}
			m.objInput, cmd = m.objInput.Update(msg)
			return m, cmd
		}

		if m.showFilter {
			switch {
			case key.Matches(msg, cliKeys.Enter), key.Matches(msg, cliKeys.Back):
				m.showFilter = false
				m.filterInput.Blur()
				m.updateData()
				return m, nil
			}
			m.filterInput, cmd = m.filterInput.Update(msg)
			m.updateData()
			return m, cmd
		}

		switch {
		case key.Matches(msg, cliKeys.Quit):
			return m, tea.Quit
		case key.Matches(msg, cliKeys.TabNext):
			m.activeTab = (m.activeTab + 1) % len(m.tabs)
		case key.Matches(msg, cliKeys.TabPrev):
			m.activeTab = (m.activeTab - 1 + len(m.tabs)) % len(m.tabs)
		case key.Matches(msg, cliKeys.Jump1):
			m.activeTab = 0
		case key.Matches(msg, cliKeys.Jump2):
			m.activeTab = 1
		case key.Matches(msg, cliKeys.Jump3):
			m.activeTab = 2
		case key.Matches(msg, cliKeys.Jump4):
			m.activeTab = 3
		case key.Matches(msg, cliKeys.Jump5):
			m.activeTab = 4
		case key.Matches(msg, cliKeys.Help):
			m.showHelp = !m.showHelp
		case key.Matches(msg, cliKeys.Top):
			if m.activeTab == 1 {
				m.logTable.GotoTop()
			} else if m.activeTab == 2 {
				m.policyTable.GotoTop()
			}
		case key.Matches(msg, cliKeys.Bottom):
			if m.activeTab == 1 {
				m.logTable.GotoBottom()
			} else if m.activeTab == 2 {
				m.policyTable.GotoBottom()
			}
		case key.Matches(msg, cliKeys.Edit):
			if m.activeTab == 3 && !m.objInputMode && m.objLevel > 0 {
				if m.objSelectedCategory < 0 || m.objSelectedCategory >= len(m.objDrafts) {
					return m, nil
				}
				entries := m.objDrafts[m.objSelectedCategory]
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
				return m, nil
			}
		case key.Matches(msg, cliKeys.Delete):
			if m.activeTab == 3 && !m.objInputMode && m.objLevel > 0 {
				m.handleObjDelete()
				return m, fetchDataCmd()
			}
		case key.Matches(msg, cliKeys.Filter):
			if m.activeTab == 1 {
				m.showFilter = true
				m.filterInput.Focus()
				m.filterInput.SetValue("")
				return m, nil
			}

		case key.Matches(msg, cliKeys.Toggle):
			if m.activeTab == 2 && len(m.draftRules) > 0 && m.editState == policyStateNormal {
				idx := m.policyTable.Cursor()
				if idx >= 0 && idx < len(m.draftRules) {
					rule := m.draftRules[idx]
					if rule.Kind != "section" {
						cliToggleRule(rule.File, rule.ID)
						return m, fetchDataCmd()
					}
				}
			}

		case key.Matches(msg, cliKeys.Move):
			if m.activeTab == 2 && len(m.draftRules) > 0 && m.editState == policyStateNormal {
				idx := m.policyTable.Cursor()
				if idx >= 0 && idx < len(m.draftRules) {
					m.editState = policyStateMoving
					m.moveSourceID = m.draftRules[idx].ID
					m.updateData() // highlight row immediately
				}
			}

		case key.Matches(msg, cliKeys.Add):
			if m.activeTab == 3 && !m.objInputMode && m.objLevel > 0 {
				m.objInputMode = true
				if m.objLevel == 1 {
					m.objInputContext = "entry_name"
				} else {
					m.objInputContext = "member_value"
				}
				m.objInput.SetValue("")
				m.objInput.Focus()
				return m, nil
			} else if m.activeTab == 2 && m.editState == policyStateNormal {
				m.editState = policyStatePrompt
				m.filterInput.Focus()
				m.filterInput.SetValue("")
			}

		case key.Matches(msg, cliKeys.Commit):
			if m.editState == policyStateNormal {
				act := activeStages()
				if len(act) == 0 {
					return m, nil
				}
				if _, err := os.Stat(sentinel); err == nil {
					if m.status == nil {
						m.status = make(map[string]interface{})
					}
					m.status["commitError"] = "a confirm is already pending on the host"
					return m, nil
				}
				msgStr, ok := validateDraft()
				if !ok {
					if m.status == nil {
						m.status = make(map[string]interface{})
					}
					m.status["commitError"] = msgStr
					return m, nil
				}
				for _, s := range act {
					backupLive(s)
				}
				for _, s := range act {
					copyFile(s.draft, s.live)
				}
				run(nftgeoBin, "apply", "--confirm", "90")
				m.editState = policyStateConfirming
				m.confirmRemaining = 90
				return m, tickCmd()
			}

		case key.Matches(msg, cliKeys.ConfirmY):
			if m.editState == policyStateConfirming {
				run(nftgeoBin, "apply", "--commit")
				for _, s := range stages() {
					os.Remove(s.draft)
					os.Remove(s.backup)
				}
				m.editState = policyStateNormal
				return m, fetchDataCmd()
			}

		case key.Matches(msg, cliKeys.ConfirmN), key.Matches(msg, cliKeys.Rollback):
			if m.editState == policyStateConfirming {
				run(nftgeoBin, "rollback")
				restoreBackups()
				m.editState = policyStateNormal
				return m, fetchDataCmd()
			} else if m.editState == policyStateNormal {
				for _, s := range stages() {
					os.Remove(s.draft)
				}
				return m, fetchDataCmd()
			}

		case key.Matches(msg, cliKeys.Enter):
			if m.activeTab == 1 && len(m.logTable.Rows()) > 0 {
				row := m.logTable.SelectedRow()
				if len(row) > 1 {
					return m, lookupCmd(row[1])
				}
			} else if m.activeTab == 2 && m.editState == policyStateMoving {
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
					cliMoveRule(sourceFile, destRule.File, sourceRuleID, localIdx)
				}
				m.editState = policyStateNormal
				return m, fetchDataCmd()
			} else if m.activeTab == 2 && m.editState == policyStatePrompt {
				m.editState = policyStateNormal
				val := strings.TrimSpace(m.filterInput.Value())
				if val != "" {
					if net.ParseIP(val) == nil {
						_, _, err := net.ParseCIDR(val)
						if err != nil {
							if m.status == nil {
								m.status = make(map[string]interface{})
							}
							m.status["commitError"] = "Invalid IP or CIDR: " + val
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
					cliAddDenyRule(file, val)
					return m, tea.Batch(fetchDataCmd(), tickCmd())
				}
			}

		case key.Matches(msg, cliKeys.Back):
			if m.activeTab == 2 && (m.editState == policyStateMoving || m.editState == policyStatePrompt) {
				m.editState = policyStateNormal
				m.updateData()
			}

		case key.Matches(msg, cliKeys.CycleV):
			if m.activeTab == 1 {
				switch m.verdictFilter {
				case "":
					m.verdictFilter = "drop"
				case "drop":
					m.verdictFilter = "accept"
				default:
					m.verdictFilter = ""
				}
				m.updateData()
			}
		case key.Matches(msg, cliKeys.CycleD):
			if m.activeTab == 1 {
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
			}
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
	}

	if msgKey, ok := msg.(tea.KeyMsg); ok {
		if m.activeTab == 3 && !m.objInputMode {
			switch {
			case key.Matches(msgKey, cliKeys.Add):
				if m.objLevel > 0 {
					m.objInputMode = true
					if m.objLevel == 1 {
						m.objInputContext = "entry_name"
					} else {
						m.objInputContext = "member_value"
					}
					m.objInput.SetValue("")
					m.objInput.Focus()
					return m, nil
				}
			case key.Matches(msgKey, cliKeys.Edit):
				if m.objLevel > 0 {
					if m.objSelectedCategory < 0 || m.objSelectedCategory >= len(m.objDrafts) {
						return m, nil
					}
					entries := m.objDrafts[m.objSelectedCategory]
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
					return m, nil
				}
			case key.Matches(msgKey, cliKeys.Delete):
				if m.objLevel > 0 {
					m.handleObjDelete()
					return m, fetchDataCmd()
				}
			}

			switch {
			case key.Matches(msgKey, cliKeys.Left):
				if m.objLevel > 0 {
					m.objLevel--
				}
			case key.Matches(msgKey, cliKeys.Right):
				if m.objLevel < 2 {
					m.objLevel++
				}
			case key.Matches(msgKey, cliKeys.Up):
				if m.objLevel == 0 && m.objSelectedCategory > 0 {
					m.objSelectedCategory--
					m.objSelectedEntry = 0
					m.objSelectedMember = 0
				} else if m.objLevel == 1 && m.objSelectedEntry > 0 {
					m.objSelectedEntry--
					m.objSelectedMember = 0
				} else if m.objLevel == 2 && m.objSelectedMember > 0 {
					m.objSelectedMember--
				}
			case key.Matches(msgKey, cliKeys.Down):
				if m.objLevel == 0 && m.objSelectedCategory < 6 {
					m.objSelectedCategory++
					m.objSelectedEntry = 0
					m.objSelectedMember = 0
				} else if m.objLevel == 1 {
					if m.objSelectedCategory >= 0 && m.objSelectedCategory < len(m.objDrafts) && m.objSelectedEntry < len(m.objDrafts[m.objSelectedCategory])-1 {
						m.objSelectedEntry++
						m.objSelectedMember = 0
					}
				} else if m.objLevel == 2 {
					if m.objSelectedCategory >= 0 && m.objSelectedCategory < len(m.objDrafts) && m.objSelectedEntry >= 0 && m.objSelectedEntry < len(m.objDrafts[m.objSelectedCategory]) {
						members := m.objDrafts[m.objSelectedCategory][m.objSelectedEntry].Members
						if m.objSelectedMember < len(members)-1 {
							m.objSelectedMember++
						}
					}
				}
			}
		}
	}

	if m.activeTab == 1 && !m.showFilter {
		m.logTable, cmd = m.logTable.Update(msg)
	} else if m.activeTab == 2 {
		m.policyTable, cmd = m.policyTable.Update(msg)
	}

	return m, cmd
}

func (m *cliModel) updateData() {
	// Update Logs Table
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
			v = cliDropVerdictStyle.Render(v)
		} else {
			v = cliAcceptVerdictStyle.Render(v)
		}

		rows = append(rows, bubblesTable.Row{
			d.Time, d.Src, d.CC, d.Dport, d.Proto, d.Reason, v,
		})
	}
	m.logTable.SetRows(rows)

	// Update Policy Table
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
				bar = cliDropVerdictStyle.Render(bar)
			} else {
				bar = cliAcceptVerdictStyle.Render(bar)
			}
		}

		row := bubblesTable.Row{
			fmt.Sprintf("%d", r.ID), r.Action, r.Dir, r.Proto, r.Port, r.Target, r.Iface, hits, bar,
		}
		if r.Disabled || !r.Matched {
			for j, val := range row {
				row[j] = cliMutedStyle.Render(val)
			}
		}
		if r.Disabled {
			row[1] = cliMutedStyle.Render(r.Action + " (disabled)")
		}
		if m.editState == policyStateMoving && m.moveSourceID == r.ID {
			for j, val := range row {
				row[j] = lipgloss.NewStyle().Background(lipgloss.Color("238")).Render(val)
			}
		}
		pRows = append(pRows, row)
	}
	m.policyTable.SetRows(pRows)

	// Update Charts
	if len(m.drops.Timeline) == 24 {
		m.dropsChart.Clear()
		maxDrops := 1.0
		for _, v := range m.drops.Timeline {
			if float64(v) > maxDrops {
				maxDrops = float64(v)
			}
		}
		// Redraw with new max
		m.dropsChart = linechart.New(m.dropsChart.Canvas.Width(), m.dropsChart.Canvas.Height(), 0, 23, 0, maxDrops)
		for i := 1; i < 24; i++ {
			p1 := canvas.Float64Point{X: float64(i - 1), Y: float64(m.drops.Timeline[i-1])}
			p2 := canvas.Float64Point{X: float64(i), Y: float64(m.drops.Timeline[i])}
			m.dropsChart.DrawBrailleLine(p1, p2)
		}
	}

	// Ingress CC
	m.ingressChart.Clear()
	var ccKeys []string
	for k := range m.drops.IngressByCC {
		ccKeys = append(ccKeys, k)
	}
	sort.Slice(ccKeys, func(i, j int) bool { return m.drops.IngressByCC[ccKeys[i]] > m.drops.IngressByCC[ccKeys[j]] })
	for i := 0; i < 10 && i < len(ccKeys); i++ {
		m.ingressChart.Push(barchart.BarData{
			Label:  ccKeys[i],
			Values: []barchart.BarValue{{Value: float64(m.drops.IngressByCC[ccKeys[i]]), Style: lipgloss.NewStyle().Foreground(lipgloss.Color("9"))}},
		})
	}
	m.ingressChart.Draw()

	// Top Ports
	m.topPortsChart.Clear()
	var portKeys []string
	for k := range m.drops.TopPorts {
		portKeys = append(portKeys, k)
	}
	sort.Slice(portKeys, func(i, j int) bool { return m.drops.TopPorts[portKeys[i]] > m.drops.TopPorts[portKeys[j]] })
	for i := 0; i < 10 && i < len(portKeys); i++ {
		m.topPortsChart.Push(barchart.BarData{
			Label:  portKeys[i],
			Values: []barchart.BarValue{{Value: float64(m.drops.TopPorts[portKeys[i]]), Style: lipgloss.NewStyle().Foreground(lipgloss.Color("12"))}},
		})
	}
	m.topPortsChart.Draw()

	// Sparklines
	if ifData, ok := m.ifStats["ifaces"].([]map[string]interface{}); ok {
		for _, iface := range ifData {
			name := iface["name"].(string)
			if _, ok := m.rxSparklines[name]; !ok {
				m.rxSparklines[name] = sparkline.New(20, 1)
				m.txSparklines[name] = sparkline.New(20, 1)
			}
			if rx, ok := iface["rx_bps"].([]float64); ok {
				sl := m.rxSparklines[name]
				sl.Clear()
				sl.PushAll(rx)
				sl.Draw()
				m.rxSparklines[name] = sl
			}
			if tx, ok := iface["tx_bps"].([]float64); ok {
				sl := m.txSparklines[name]
				sl.Clear()
				sl.PushAll(tx)
				sl.Draw()
				m.txSparklines[name] = sl
			}
		}
	}
}

func (m *cliModel) updateLayout() {
	m.help.Width = m.width
	m.logTable.SetHeight(m.height - 12)
	m.policyTable.SetHeight(m.height - 15)
	m.viewport.Width = m.width - 10
	m.viewport.Height = m.height - 10

	m.dropsChart.Resize(m.width-10, 10)
	m.ingressChart.Resize((m.width-15)/2, 10)
	m.topPortsChart.Resize((m.width-15)/2, 10)
}

// ---- view ----

func (m cliModel) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	header := cliHeaderStyle.Render(fmt.Sprintf("nftgeo-ui console • %s", version()))

	var renderedTabs []string
	for i, t := range m.tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, cliActiveTabStyle.Render(t))
		} else {
			renderedTabs = append(renderedTabs, cliTabStyle.Render(t))
		}
	}
	tabsRow := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)

	var content string
	if m.loading {
		content = "\n\n  Loading data from firewall..."
	} else {
		switch m.activeTab {
		case 0:
			content = m.renderDashboard()
		case 1:
			content = m.renderLogs()
		case 2:
			content = m.renderPolicy()
		case 3:
			content = m.renderObjects()
		case 4:
			content = m.renderSystem()
		}
	}

	mainContent := cliWindowStyle.Width(m.width - 4).Height(m.height - 6).Render(content)

	footer := m.help.View(cliKeys)
	if m.showHelp {
		footer = m.help.FullHelpView(cliKeys.FullHelp())
	}

	view := lipgloss.JoinVertical(lipgloss.Left, header, tabsRow, mainContent, footer)

	if m.showLookup {
		modal := cliModalStyle.Render(m.viewport.View())
		return m.placeCenter(modal, view)
	}

	return view
}

func (m cliModel) renderKPI(label, value string) string {
	return cliKpiStyle.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			cliKpiLabelStyle.Render(label),
			cliKpiValueStyle.Render(value),
		),
	)
}

func (m cliModel) renderDashboard() string {
	ingressTotal := 0
	for _, v := range m.drops.IngressByCC {
		ingressTotal += v
	}
	egressTotal := 0
	for _, v := range m.drops.EgressByCC {
		egressTotal += v
	}

	rxTotal, txTotal := 0.0, 0.0
	if ifaces, ok := m.ifStats["ifaces"].([]map[string]interface{}); ok {
		for _, iface := range ifaces {
			if rx, ok := iface["rx_bps"].([]float64); ok && len(rx) > 0 {
				rxTotal += rx[len(rx)-1]
			}
			if tx, ok := iface["tx_bps"].([]float64); ok && len(tx) > 0 {
				txTotal += tx[len(tx)-1]
			}
		}
	}

	kpiRow := lipgloss.JoinHorizontal(lipgloss.Top,
		m.renderKPI("Drops/24h", fmt.Sprintf("%d", m.drops.Total)),
		m.renderKPI("Ingress", fmt.Sprintf("%d", ingressTotal)),
		m.renderKPI("Egress", fmt.Sprintf("%d", egressTotal)),
		m.renderKPI("Abuse IPs", fmt.Sprintf("%d", abuseLoadedCount())),
		m.renderKPI("Conntrack", m.getConntrack()),
		m.renderKPI("Net RX/TX", fmt.Sprintf("%s / %s", formatBpsVal(rxTotal), formatBpsVal(txTotal))),
	)

	chartTitle := lipgloss.NewStyle().Bold(true).MarginBottom(0).Render("Drops over 24h")
	chart := m.dropsChart.View()

	bottomCharts := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.JoinVertical(lipgloss.Left, lipgloss.NewStyle().Bold(true).Render("Top Countries"), m.ingressChart.View()),
		lipgloss.JoinVertical(lipgloss.Left, lipgloss.NewStyle().Bold(true).Render("Top Ports"), m.topPortsChart.View()),
	)

	systemLine := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render(
		fmt.Sprintf("Table: %s • Last Fetch: %s",
			map[bool]string{true: "LOADED", false: "NOT LOADED"}[m.status["loaded"].(bool)],
			m.lastFetch.Format("15:04:05")),
	)

	return lipgloss.JoinVertical(lipgloss.Left, kpiRow, "", chartTitle, chart, "", bottomCharts, "", systemLine)
}

func (m cliModel) getConntrack() string {
	if ct, ok := m.ifStats["conntrack"].(map[string]uint64); ok {
		return fmt.Sprintf("%d / %d", ct["count"], ct["max"])
	}
	return "n/a"
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

	fLine := lipgloss.NewStyle().Foreground(lipgloss.Color("241")).Render(filterInfo)
	if m.showFilter {
		fLine = lipgloss.JoinHorizontal(lipgloss.Top,
			lipgloss.NewStyle().Foreground(lipgloss.Color("12")).Bold(true).Render("FIND: "),
			m.filterInput.View(),
		)
	}

	return lipgloss.JoinVertical(lipgloss.Left, fLine, "", m.logTable.View())
}

func (m cliModel) renderPolicy() string {
	base := ""
	if m.editState == policyStateConfirming {
		base = cliDropVerdictStyle.Render(fmt.Sprintf("PENDING CONFIRM: Press 'y' to KEEP, 'n' to ROLLBACK (%ds remaining)\n\n", m.confirmRemaining))
	} else if err, ok := m.status["commitError"].(string); ok && err != "" {
		base = lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render(fmt.Sprintf("VALIDATION ERROR: %s\n\n", err))
	} else if m.editState == policyStateMoving {
		base = lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render("MOVE MODE: Use j/k to move rule, Enter to place, Esc to cancel.\n\n")
	} else if m.editState == policyStatePrompt {
		base = lipgloss.JoinHorizontal(lipgloss.Top,
			lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Bold(true).Render("ADD DENY RULE (Enter target/IP): "),
			m.filterInput.View(),
		) + "\n\n"
	}

	if m.baseline != nil {
		input := m.baseline["input"]
		base = fmt.Sprintf("Default Policies: INPUT=%s  FORWARD=%s  OUTPUT=%s\n",
			input["policy"], m.baseline["forward"]["policy"], m.baseline["output"]["policy"])
		base += fmt.Sprintf("Established: %v  Whitelist: %v  Invalid: %v\n\n",
			input["established"], input["whitelist"], input["invalid"])
	}
	return base + m.policyTable.View()
}

func (m cliModel) renderObjects() string {
	if m.editState == policyStateConfirming {
		return cliDropVerdictStyle.Render(fmt.Sprintf("PENDING CONFIRM: Press 'y' to KEEP, 'n' to ROLLBACK (%ds remaining)\n\n", m.confirmRemaining))
	}
	if m.objDrafts == nil {
		return "Loading..."
	}

	var sb strings.Builder

	if errStr, ok := m.status["commitError"].(string); ok && errStr != "" {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render("Error: "+errStr) + "\n\n")
	} else if m.objHasDraft {
		sb.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("11")).Render("* Unsaved Draft (Press 'c' to commit)") + "\n\n")
	} else {
		sb.WriteString("\n\n")
	}

	cats := []string{"Groups", "Regions", "Services", "Hosts", "Zones", "Lists", "Feeds"}

	colWidth := (m.width - 10) / 3
	if colWidth < 20 {
		colWidth = 20
	}

	styleNormal := lipgloss.NewStyle().Width(colWidth).Padding(0, 1)
	styleSelected := lipgloss.NewStyle().Width(colWidth).Padding(0, 1).Foreground(lipgloss.Color("0")).Background(lipgloss.Color("14"))
	styleDimmed := lipgloss.NewStyle().Width(colWidth).Padding(0, 1).Foreground(lipgloss.Color("240"))

	var catView strings.Builder
	for i, c := range cats {
		s := styleNormal
		if m.objLevel == 0 && i == m.objSelectedCategory {
			s = styleSelected
		} else if i == m.objSelectedCategory {
			s = lipgloss.NewStyle().Width(colWidth).Padding(0, 1).Foreground(lipgloss.Color("14")).Bold(true)
		} else if m.objLevel > 0 {
			s = styleDimmed
		}
		catView.WriteString(s.Render(c) + "\n")
	}

	var entView strings.Builder
	var memView strings.Builder

	if m.objSelectedCategory >= 0 && m.objSelectedCategory < len(m.objDrafts) {
		entries := m.objDrafts[m.objSelectedCategory]

		if m.objInputMode && m.objLevel == 1 {
			entView.WriteString(styleSelected.Render("> "+m.objInput.View()) + "\n")
		}

		for i, e := range entries {
			s := styleNormal
			if m.objLevel == 1 && i == m.objSelectedEntry && !m.objInputMode {
				s = styleSelected
			} else if i == m.objSelectedEntry && m.objLevel > 1 {
				s = lipgloss.NewStyle().Width(colWidth).Padding(0, 1).Foreground(lipgloss.Color("14")).Bold(true)
			} else if m.objLevel > 1 {
				s = styleDimmed
			} else if m.objLevel == 0 {
				s = styleDimmed
			}
			entView.WriteString(s.Render(e.Name) + "\n")
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

func (m cliModel) renderSystem() string {
	var sb strings.Builder
	if ifaces, ok := m.ifStats["ifaces"].([]map[string]interface{}); ok {
		for _, iface := range ifaces {
			name := iface["name"].(string)
			up := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render("DOWN")
			if iface["up"].(bool) {
				up = lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Render("UP")
			}

			flags := ""
			if iface["veth"].(bool) {
				flags += " [veth]"
			}
			if iface["bridge"].(bool) {
				flags += " [bridge]"
			}

			sb.WriteString(fmt.Sprintf("%-10s [%s] Speed: %d Mbps %s\n", name, up, iface["speed_mbps"], flags))
			sb.WriteString("  RX: " + m.rxSparklines[name].View() + " " + formatBps(iface["rx_bps"].([]float64)))
			if errs, ok := iface["errors"].(map[string]uint64); ok && errs["rx_errs"] > 0 {
				sb.WriteString(cliDropVerdictStyle.Render(fmt.Sprintf(" (Errs: %d)", errs["rx_errs"])))
			}
			sb.WriteString("\n")

			sb.WriteString("  TX: " + m.txSparklines[name].View() + " " + formatBps(iface["tx_bps"].([]float64)))
			if errs, ok := iface["errors"].(map[string]uint64); ok && errs["tx_errs"] > 0 {
				sb.WriteString(cliDropVerdictStyle.Render(fmt.Sprintf(" (Errs: %d)", errs["tx_errs"])))
			}
			sb.WriteString("\n\n")
		}
	}
	return sb.String()
}

func formatBpsVal(val float64) string {
	if val > 1000000 {
		return fmt.Sprintf("%.1f Mbps", val/1000000)
	}
	if val > 1000 {
		return fmt.Sprintf("%.1f Kbps", val/1000)
	}
	return fmt.Sprintf("%.0f bps", val)
}

func formatBps(data []float64) string {
	if len(data) == 0 {
		return "0 bps"
	}
	return formatBpsVal(data[len(data)-1])
}

func (m cliModel) renderLookupDetails() string {
	if m.lookupRes == nil {
		return "Loading..."
	}
	ip := m.lookupRes["ip"].(string)
	res := fmt.Sprintf("Lookup for: %s\n\n", lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12")).Render(ip))

	if ptr, ok := m.lookupRes["ptr"].([]string); ok {
		res += lipgloss.NewStyle().Bold(true).Render("Reverse DNS:") + "\n"
		for _, n := range ptr {
			res += "  " + n + "\n"
		}
		res += "\n"
	}

	if rdap, ok := m.lookupRes["rdap"].(map[string]interface{}); ok {
		res += lipgloss.NewStyle().Bold(true).Render("RDAP Information:") + "\n"
		res += fmt.Sprintf("  Org:     %v\n", rdap["org"])
		res += fmt.Sprintf("  CIDR:    %v\n", rdap["cidr"])
		res += fmt.Sprintf("  Country: %v\n", rdap["country"])
		res += fmt.Sprintf("  Handle:  %v\n", rdap["handle"])
	}

	res += "\n\nPress ESC to close"
	return res
}

func (m cliModel) placeCenter(modal, bg string) string {
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal, lipgloss.WithWhitespaceChars(" "), lipgloss.WithWhitespaceForeground(lipgloss.Color("232")))
}

func startCLI() {
	reconcileCommit()
	p := tea.NewProgram(initialModel(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error starting CLI: %v", err)
		os.Exit(1)
	}
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

	if m.objInputContext == "entry_name" {
		for _, e := range entries {
			if e.Name == val {
				return
			}
		}
		entries = append(entries, objEntry{Name: val, Members: []string{}})
		m.objDrafts[m.objSelectedCategory] = entries
	} else if m.objInputContext == "member_value" {
		if m.objSelectedEntry >= len(entries) {
			return
		}
		entries[m.objSelectedEntry].Members = append(entries[m.objSelectedEntry].Members, val)
		m.objDrafts[m.objSelectedCategory] = entries
	} else if m.objInputContext == "edit_entry" {
		if m.objSelectedEntry >= len(entries) {
			return
		}
		for i, e := range entries {
			if i != m.objSelectedEntry && e.Name == val {
				return // duplicate
			}
		}
		entries[m.objSelectedEntry].Name = val
		m.objDrafts[m.objSelectedCategory] = entries
	} else if m.objInputContext == "edit_member" {
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

func (m *cliModel) saveObjectsDraft() {
	if len(m.objDrafts) < 7 {
		return
	}
	g := m.objDrafts[0]
	rg := m.objDrafts[1]
	sv := m.objDrafts[2]
	hs := m.objDrafts[3]
	zn := m.objDrafts[4]
	ls := m.objDrafts[5]
	fd := m.objDrafts[6]

	err := sanitizeObjects(g, rg, sv, hs, zn, ls, fd)
	if err != nil {
		if m.status == nil {
			m.status = make(map[string]interface{})
		}
		m.status["commitError"] = "Invalid object: " + err.Error()
		return
	}

	out := serializeObjects(g, rg, sv, hs, zn, ls, fd)
	os.WriteFile(objDraftFile, []byte(out), 0644)
	m.objHasDraft = true
	if m.status != nil {
		m.status["commitError"] = ""
	}
}
