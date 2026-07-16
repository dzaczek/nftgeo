package main

// Console TUI (nftgeo-ui cli) core: model, chrome (header/tabs/status bar),
// global key handling and the per-view dispatch. Each tab's keys and renderer
// live in cli_<view>.go; every mutation goes through the same shared functions
// the web handlers use (commitApply/commitKeep/commitRollback, saveRuleDraft,
// writeObjectsDraft, ...), so the two UIs cannot drift.

import (
	"fmt"
	"os"
	"time"

	"github.com/NimbleMarkets/ntcharts/barchart"
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

type cliPalette struct {
	Bg       lipgloss.Color
	Fg       lipgloss.Color
	Muted    lipgloss.Color
	Accent   lipgloss.Color
	Drop     lipgloss.Color
	Ok       lipgloss.Color
	Line     lipgloss.Color
	Header   lipgloss.Color
	Selected lipgloss.Color
}

var (
	cliDarkPalette = cliPalette{
		Bg:       lipgloss.Color("233"),
		Fg:       lipgloss.Color("7"),
		Muted:    lipgloss.Color("241"),
		Accent:   lipgloss.Color("39"),
		Drop:     lipgloss.Color("9"),
		Ok:       lipgloss.Color("10"),
		Line:     lipgloss.Color("238"),
		Header:   lipgloss.Color("24"),
		Selected: lipgloss.Color("236"),
	}

	cliLightPalette = cliPalette{
		Bg:       lipgloss.Color("255"),
		Fg:       lipgloss.Color("235"),
		Muted:    lipgloss.Color("246"),
		Accent:   lipgloss.Color("27"),
		Drop:     lipgloss.Color("1"),
		Ok:       lipgloss.Color("2"),
		Line:     lipgloss.Color("251"),
		Header:   lipgloss.Color("31"),
		Selected: lipgloss.Color("253"),
	}
)

type cliStyles struct {
	Header        lipgloss.Style
	Tab           lipgloss.Style
	ActiveTab     lipgloss.Style
	Window        lipgloss.Style
	Kpi           lipgloss.Style
	KpiLabel      lipgloss.Style
	KpiValue      lipgloss.Style
	TableHeader   lipgloss.Style
	TableSelected lipgloss.Style
	Help          lipgloss.Style
	Modal         lipgloss.Style
	DropVerdict   lipgloss.Style
	AcceptVerdict lipgloss.Style
	Muted         lipgloss.Style
	Accent        lipgloss.Style
	Warning       lipgloss.Style
	Highlight     lipgloss.Style
	Dim           lipgloss.Style
	Banner        lipgloss.Style
	StatusErr     lipgloss.Style
	StatusInfo    lipgloss.Style
	PanelTitle    lipgloss.Style
}

func getStyles(dark bool) cliStyles {
	p := cliDarkPalette
	if !dark {
		p = cliLightPalette
	}

	s := cliStyles{}
	s.Header = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("7")).Background(p.Header).Padding(0, 1)
	s.Tab = lipgloss.NewStyle().Padding(0, 2).Border(lipgloss.NormalBorder(), false, true, false, false).BorderForeground(p.Line).Foreground(p.Muted)
	s.ActiveTab = s.Tab.Copy().Foreground(p.Ok).Bold(true)
	s.Window = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(p.Line).Padding(0, 1).Foreground(p.Fg)
	s.Kpi = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(p.Line).Padding(0, 1).MarginRight(1)
	s.KpiLabel = lipgloss.NewStyle().Foreground(p.Muted)
	s.KpiValue = lipgloss.NewStyle().Bold(true).Foreground(p.Ok)
	s.TableHeader = lipgloss.NewStyle().BorderStyle(lipgloss.NormalBorder()).BorderForeground(p.Line).BorderBottom(true).Bold(true)
	s.TableSelected = lipgloss.NewStyle().Background(p.Selected).Foreground(p.Fg)
	s.Help = lipgloss.NewStyle().Foreground(p.Muted)
	s.Modal = lipgloss.NewStyle().Border(lipgloss.DoubleBorder()).BorderForeground(p.Accent).Padding(1, 2).Background(p.Bg).Foreground(p.Fg)
	s.DropVerdict = lipgloss.NewStyle().Foreground(p.Drop)
	s.AcceptVerdict = lipgloss.NewStyle().Foreground(p.Ok)
	s.Muted = lipgloss.NewStyle().Foreground(p.Muted)
	s.Accent = lipgloss.NewStyle().Foreground(p.Accent)
	s.Warning = lipgloss.NewStyle().Foreground(lipgloss.Color("11"))
	s.Highlight = lipgloss.NewStyle().Background(p.Line)
	s.Dim = lipgloss.NewStyle().Foreground(p.Bg)
	s.Banner = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("0")).Background(p.Drop).Padding(0, 1)
	s.StatusErr = lipgloss.NewStyle().Foreground(p.Drop).Bold(true)
	s.StatusInfo = lipgloss.NewStyle().Foreground(p.Muted)
	s.PanelTitle = lipgloss.NewStyle().Bold(true).Foreground(p.Accent)
	return s
}

// ---- keys ----
//
// Keys are split into a global chrome map (tabs, help, theme, refresh, the
// commit workflow) and one small map per view. The Update loop dispatches
// view keys only to the active tab, so views can reuse letters freely — the
// old single keymap made h/l/enter/d/n/r collide across tabs and left the
// Objects tree unreachable.

type globalKeyMap struct {
	TabNext  key.Binding
	TabPrev  key.Binding
	Jump1    key.Binding
	Jump2    key.Binding
	Jump3    key.Binding
	Jump4    key.Binding
	Jump5    key.Binding
	Help     key.Binding
	Quit     key.Binding
	Theme    key.Binding
	Refresh  key.Binding
	Commit   key.Binding
	Discard  key.Binding
	ConfirmY key.Binding
	ConfirmN key.Binding
}

func (k globalKeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit}
}

func (k globalKeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.TabNext, k.TabPrev, k.Jump1, k.Jump5},
		{k.Commit, k.Discard, k.ConfirmY, k.ConfirmN},
		{k.Theme, k.Refresh, k.Help, k.Quit},
	}
}

var globalKeys = globalKeyMap{
	TabNext:  key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next tab")),
	TabPrev:  key.NewBinding(key.WithKeys("shift+tab"), key.WithHelp("s-tab", "prev tab")),
	Jump1:    key.NewBinding(key.WithKeys("1"), key.WithHelp("1", "dashboard")),
	Jump2:    key.NewBinding(key.WithKeys("2"), key.WithHelp("2", "logs")),
	Jump3:    key.NewBinding(key.WithKeys("3"), key.WithHelp("3", "policy")),
	Jump4:    key.NewBinding(key.WithKeys("4"), key.WithHelp("4", "objects")),
	Jump5:    key.NewBinding(key.WithKeys("5"), key.WithHelp("5", "system")),
	Help:     key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	Quit:     key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Theme:    key.NewBinding(key.WithKeys("t"), key.WithHelp("t", "theme")),
	Refresh:  key.NewBinding(key.WithKeys("R"), key.WithHelp("R", "refresh rate")),
	Commit:   key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "commit drafts")),
	Discard:  key.NewBinding(key.WithKeys("r"), key.WithHelp("r", "discard drafts")),
	ConfirmY: key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "keep deploy")),
	ConfirmN: key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "roll back")),
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
	activeTab       int
	tabs            []string
	width           int
	height          int
	darkTheme       bool
	refreshInterval time.Duration
	styles          cliStyles
	hostname        string

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

	// status bar (replaces the old status["commitError"] plumbing)
	statusMsg string
	statusErr bool

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

	host, _ := os.Hostname()

	m := cliModel{
		activeTab:    0,
		tabs:         []string{"Dashboard", "Logs", "Policy", "Objects", "System"},
		rxSparklines: make(map[string]sparkline.Model),
		txSparklines: make(map[string]sparkline.Model),
		help:         help.New(),
		filterInput:  ti,
		loading:      true,
		hostname:     host,

		objLevel:            0,
		objSelectedCategory: 0,
		objInput:            textinput.New(),
		darkTheme:           true,
	}
	m.styles = getStyles(m.darkTheme)

	m.logTable = bubblesTable.New(
		bubblesTable.WithColumns(logColumns(defaultViewWidth)),
		bubblesTable.WithFocused(true),
	)
	m.policyTable = bubblesTable.New(
		bubblesTable.WithColumns(policyColumns(defaultViewWidth)),
		bubblesTable.WithFocused(true),
	)
	m.updateStyles()

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

// defaultViewWidth sizes tables before the first WindowSizeMsg arrives.
const defaultViewWidth = 100

// ---- responsive column layout ----

type colSpec struct {
	title  string
	min    int // content width floor
	weight int // 0 = fixed at min; leftover space is split by weight
}

// layoutCols distributes total content width among columns: every column gets
// its min, then any leftover space is divided proportionally by weight. When
// total is smaller than the sum of minimums the minimums are kept (the table
// clips) — degrading a too-narrow terminal beats corrupting every row.
func layoutCols(total int, specs []colSpec) []int {
	widths := make([]int, len(specs))
	need, weights := 0, 0
	for i, s := range specs {
		widths[i] = s.min
		need += s.min
		weights += s.weight
	}
	extra := total - need
	if extra <= 0 || weights == 0 {
		return widths
	}
	given := 0
	last := -1
	for i, s := range specs {
		if s.weight == 0 {
			continue
		}
		add := extra * s.weight / weights
		widths[i] += add
		given += add
		last = i
	}
	if last >= 0 {
		widths[last] += extra - given // remainder to the last flexible column
	}
	return widths
}

func toTableColumns(specs []colSpec, widths []int) []bubblesTable.Column {
	cols := make([]bubblesTable.Column, len(specs))
	for i, s := range specs {
		cols[i] = bubblesTable.Column{Title: s.title, Width: widths[i]}
	}
	return cols
}

// ---- defensive map access ----
//
// The fetched status/ifStats maps come from functions that may change shape;
// a missing or differently-typed key must degrade, never panic the render.

func asStr(m map[string]interface{}, k string) string {
	if m == nil {
		return ""
	}
	s, _ := m[k].(string)
	return s
}

func asBool(m map[string]interface{}, k string) bool {
	if m == nil {
		return false
	}
	b, _ := m[k].(bool)
	return b
}

func asInt(m map[string]interface{}, k string) int {
	if m == nil {
		return 0
	}
	switch v := m[k].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case uint64:
		return int(v)
	case float64:
		return int(v)
	}
	return 0
}

func asF64s(m map[string]interface{}, k string) []float64 {
	if m == nil {
		return nil
	}
	f, _ := m[k].([]float64)
	return f
}

func asIfaceList(m map[string]interface{}, k string) []map[string]interface{} {
	if m == nil {
		return nil
	}
	l, _ := m[k].([]map[string]interface{})
	return l
}

// ---- status bar ----

func (m *cliModel) setStatusErr(msg string) {
	m.statusMsg = msg
	m.statusErr = true
}

func (m *cliModel) setStatusInfo(msg string) {
	m.statusMsg = msg
	m.statusErr = false
}

func (m *cliModel) clearStatus() {
	m.statusMsg = ""
	m.statusErr = false
}

// ---- commands ----

type refreshTickMsg time.Time
type confirmTickMsg time.Time
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

func refreshTickCmd(d time.Duration) tea.Cmd {
	if d <= 0 {
		return nil
	}
	return tea.Tick(d, func(t time.Time) tea.Msg {
		return refreshTickMsg(t)
	})
}

func confirmTickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return confirmTickMsg(t)
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
	return tea.Batch(fetchDataCmd(), refreshTickCmd(m.refreshInterval))
}

func (m cliModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case refreshTickMsg:
		return m, tea.Batch(fetchDataCmd(), refreshTickCmd(m.refreshInterval))

	case confirmTickMsg:
		if m.editState == policyStateConfirming {
			m.confirmRemaining--
			if m.confirmRemaining <= 0 {
				// The engine deadman fires on the host and watchDeadman (armed
				// by commitApply) restores the file backups — nothing to run
				// here, just leave confirm mode and refetch.
				m.editState = policyStateNormal
				m.setStatusInfo("deadman expired — deploy rolled back")
				return m, fetchDataCmd()
			}
			return m, confirmTickCmd()
		}
		return m, nil

	case fetchMsg:
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
		return m.updateKeys(msg)

	case tea.MouseMsg:
		if msg.Action == tea.MouseActionPress && msg.Button == tea.MouseButtonLeft {
			// Tab click detection (tabs render on terminal row 1, under the header)
			if msg.Y == 1 {
				x := 0
				for i, t := range m.tabs {
					w := lipgloss.Width(m.styles.Tab.Render(t))
					if msg.X >= x && msg.X < x+w {
						m.activeTab = i
						return m, nil
					}
					x += w
				}
			}
		}
		if m.showLookup {
			m.viewport, cmd = m.viewport.Update(msg)
			return m, cmd
		}
		if m.activeTab == 1 && !m.showFilter {
			m.logTable, cmd = m.logTable.Update(msg)
			return m, cmd
		} else if m.activeTab == 2 {
			m.policyTable, cmd = m.policyTable.Update(msg)
			return m, cmd
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
	}

	return m, cmd
}

// updateKeys routes one key press: text inputs and modals own the keyboard
// first, then the pending-confirm workflow, then global chrome keys, then the
// active view's own keymap.
func (m cliModel) updateKeys(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd

	// 1) modal / input ownership
	if m.showLookup {
		switch {
		case key.Matches(msg, viewKeyBack), key.Matches(msg, globalKeys.Quit):
			m.showLookup = false
			return m, nil
		}
		m.viewport, cmd = m.viewport.Update(msg)
		return m, cmd
	}
	if m.activeTab == 3 && m.objInputMode {
		return m.updateObjectsInput(msg)
	}
	if m.showFilter {
		switch {
		case key.Matches(msg, viewKeyEnter), key.Matches(msg, viewKeyBack):
			m.showFilter = false
			m.filterInput.Blur()
			m.updateData()
			return m, nil
		}
		m.filterInput, cmd = m.filterInput.Update(msg)
		m.updateData()
		return m, cmd
	}
	if m.editState == policyStatePrompt {
		return m.updatePolicyPrompt(msg)
	}

	// 2) pending confirm: y keeps, n/r rolls back; q is guarded
	if m.editState == policyStateConfirming {
		switch {
		case key.Matches(msg, globalKeys.ConfirmY):
			if _, errMsg, _ := commitKeep(); errMsg != "" {
				m.setStatusErr(errMsg)
			} else {
				m.setStatusInfo("deploy kept")
			}
			m.editState = policyStateNormal
			return m, fetchDataCmd()
		case key.Matches(msg, globalKeys.ConfirmN), key.Matches(msg, globalKeys.Discard):
			commitRollback()
			m.editState = policyStateNormal
			m.setStatusInfo("deploy rolled back")
			return m, fetchDataCmd()
		case key.Matches(msg, globalKeys.Quit):
			if msg.String() == "ctrl+c" {
				return m, tea.Quit
			}
			m.setStatusErr("deploy pending — press y to keep or n to roll back first")
			return m, nil
		}
		// fall through: allow tab switching etc. while the countdown runs
	}

	// 3) global chrome keys
	switch {
	case key.Matches(msg, globalKeys.Quit):
		return m, tea.Quit
	case key.Matches(msg, globalKeys.TabNext):
		m.activeTab = (m.activeTab + 1) % len(m.tabs)
		return m, nil
	case key.Matches(msg, globalKeys.TabPrev):
		m.activeTab = (m.activeTab - 1 + len(m.tabs)) % len(m.tabs)
		return m, nil
	case key.Matches(msg, globalKeys.Jump1):
		m.activeTab = 0
		return m, nil
	case key.Matches(msg, globalKeys.Jump2):
		m.activeTab = 1
		return m, nil
	case key.Matches(msg, globalKeys.Jump3):
		m.activeTab = 2
		return m, nil
	case key.Matches(msg, globalKeys.Jump4):
		m.activeTab = 3
		return m, nil
	case key.Matches(msg, globalKeys.Jump5):
		m.activeTab = 4
		return m, nil
	case key.Matches(msg, globalKeys.Help):
		m.showHelp = !m.showHelp
		return m, nil
	case key.Matches(msg, globalKeys.Theme):
		m.darkTheme = !m.darkTheme
		m.updateStyles()
		m.updateData()
		return m, nil
	case key.Matches(msg, globalKeys.Refresh):
		switch m.refreshInterval {
		case 0:
			m.refreshInterval = 2 * time.Second
		case 2 * time.Second:
			m.refreshInterval = 5 * time.Second
		case 5 * time.Second:
			m.refreshInterval = 10 * time.Second
		default:
			m.refreshInterval = 0
		}
		if m.refreshInterval > 0 {
			return m, refreshTickCmd(m.refreshInterval)
		}
		return m, nil
	case key.Matches(msg, globalKeys.Commit):
		if m.editState == policyStateNormal {
			return m.startCommit()
		}
		return m, nil
	case key.Matches(msg, globalKeys.Discard):
		// Discard is destructive; only offer it where the draft workflow
		// lives (Policy, Objects), and never during a pending confirm.
		if m.editState == policyStateNormal && (m.activeTab == 2 || m.activeTab == 3) {
			if len(activeStages()) == 0 {
				m.setStatusInfo("no drafts to discard")
				return m, nil
			}
			for _, s := range stages() {
				os.Remove(s.draft)
			}
			m.setStatusInfo("drafts discarded")
			return m, fetchDataCmd()
		}
		// not a chrome action here — let the view use the key
	}

	// 4) per-view keys
	switch m.activeTab {
	case 1:
		return m.updateLogsKeys(msg)
	case 2:
		return m.updatePolicyKeys(msg)
	case 3:
		return m.updateObjectsKeys(msg)
	}
	return m, nil
}

// startCommit runs the shared deploy pipeline (same as the web Commit button).
func (m cliModel) startCommit() (tea.Model, tea.Cmd) {
	if len(activeStages()) == 0 {
		m.setStatusInfo("no drafts to deploy")
		return m, nil
	}
	payload, errMsg, _ := commitApply(90)
	if errMsg != "" {
		m.setStatusErr(errMsg)
		return m, nil
	}
	if deployed, _ := payload["deployed"].(bool); !deployed {
		if s, _ := payload["message"].(string); s != "" {
			m.setStatusErr(s)
		}
		return m, nil
	}
	m.editState = policyStateConfirming
	m.confirmRemaining = 90
	if s, ok := payload["seconds"].(int); ok {
		m.confirmRemaining = s
	}
	m.clearStatus()
	return m, confirmTickCmd()
}

// ---- shared view key bindings (enter/esc reused by every view) ----

var (
	viewKeyEnter = key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select"))
	viewKeyBack  = key.NewBinding(key.WithKeys("esc", "backspace"), key.WithHelp("esc", "back"))
	viewKeyUp    = key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up"))
	viewKeyDown  = key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down"))
	viewKeyTop   = key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "top"))
	viewKeyBot   = key.NewBinding(key.WithKeys("G"), key.WithHelp("G", "bottom"))
)

// ---- data -> widgets ----

func (m *cliModel) updateData() {
	m.updateLogsData()
	m.updatePolicyData()
	m.updateDashboardData()
	m.updateSystemData()
}

func (m *cliModel) updateStyles() {
	m.styles = getStyles(m.darkTheme)
	ts := bubblesTable.DefaultStyles()
	ts.Header = m.styles.TableHeader
	ts.Selected = m.styles.TableSelected
	m.logTable.SetStyles(ts)
	m.policyTable.SetStyles(ts)
	m.help.Styles.ShortKey = m.styles.Accent
	m.help.Styles.ShortDesc = m.styles.Muted
	m.help.Styles.FullKey = m.styles.Accent
	m.help.Styles.FullDesc = m.styles.Muted
	m.filterInput.TextStyle = m.styles.Accent
	m.filterInput.PlaceholderStyle = m.styles.Muted
}

// viewWidth is the content width inside the window border/padding.
func (m *cliModel) viewWidth() int {
	w := m.width - 6
	if w < 40 {
		w = 40
	}
	return w
}

func (m *cliModel) updateLayout() {
	m.help.Width = m.width
	vw := m.viewWidth()

	m.logTable.SetColumns(logColumns(vw))
	m.logTable.SetHeight(m.height - 10)
	m.policyTable.SetColumns(policyColumns(vw))
	m.policyTable.SetHeight(m.height - 13)
	m.viewport.Width = m.width - 10
	m.viewport.Height = m.height - 10

	m.dropsChart.Resize(vw-2, 10)
	m.ingressChart.Resize((vw-5)/2, 10)
	m.topPortsChart.Resize((vw-5)/2, 10)
	m.updateData()
}

// ---- view ----

func (m cliModel) View() string {
	if m.width == 0 {
		return "Initializing..."
	}

	header := m.renderHeader()

	var renderedTabs []string
	for i, t := range m.tabs {
		if i == m.activeTab {
			renderedTabs = append(renderedTabs, m.styles.ActiveTab.Render(t))
		} else {
			renderedTabs = append(renderedTabs, m.styles.Tab.Render(t))
		}
	}
	tabsRow := lipgloss.JoinHorizontal(lipgloss.Top, renderedTabs...)

	banner := ""
	bannerLines := 0
	if m.editState == policyStateConfirming {
		banner = m.styles.Banner.Width(m.width).Render(
			fmt.Sprintf("⏳ DEPLOY PENDING — y keep · n roll back · auto-rollback in %ds", m.confirmRemaining))
		bannerLines = 1
	}

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

	// header(1) + tabs(1) + banner(0/1) + window border(2) + status(1) + hints(1)
	contentH := m.height - 6 - bannerLines
	if contentH < 4 {
		contentH = 4
	}
	mainContent := m.styles.Window.Width(m.width - 2).Height(contentH).Render(content)

	statusLine := m.renderStatusBar()
	hints := m.renderHints()

	parts := []string{header, tabsRow}
	if banner != "" {
		parts = append(parts, banner)
	}
	parts = append(parts, mainContent, statusLine, hints)
	view := lipgloss.JoinVertical(lipgloss.Left, parts...)

	if m.showLookup {
		modal := m.styles.Modal.Render(m.viewport.View())
		return m.placeOverlay(modal)
	}

	return view
}

// renderHeader is the k9s-style context line: what box, what state, how live.
func (m cliModel) renderHeader() string {
	left := fmt.Sprintf("nftgeo console • %s", asStr(m.status, "version"))
	if m.hostname != "" {
		left += " • " + m.hostname
	}

	loaded := "table: –"
	if asBool(m.status, "loaded") {
		loaded = "table: LOADED"
	}
	refreshStr := m.refreshInterval.String()
	if m.refreshInterval <= 0 {
		refreshStr = "off"
	}
	right := loaded + " • refresh: " + refreshStr
	if len(activeStages()) > 0 {
		right += " • ● draft pending"
	}

	gap := m.width - lipgloss.Width(left) - lipgloss.Width(right) - 4
	if gap < 1 {
		gap = 1
	}
	return m.styles.Header.Width(m.width).Render(left + fmt.Sprintf("%*s", gap, "") + right)
}

func (m cliModel) renderStatusBar() string {
	if m.statusMsg == "" {
		return m.styles.StatusInfo.Render(fmt.Sprintf(" last fetch %s", m.lastFetch.Format("15:04:05")))
	}
	if m.statusErr {
		return m.styles.StatusErr.Render(" ✗ " + m.statusMsg)
	}
	return m.styles.StatusInfo.Render(" ✓ " + m.statusMsg)
}

// renderHints shows the active view's keys plus the global chrome keys.
func (m cliModel) renderHints() string {
	if m.showHelp {
		return m.help.FullHelpView(globalKeys.FullHelp())
	}
	var viewHints string
	switch m.activeTab {
	case 1:
		viewHints = logsHints
	case 2:
		viewHints = policyHints
	case 3:
		viewHints = objectsHints
	default:
		viewHints = ""
	}
	global := "1-5 tabs · c commit · t theme · R rate · ? help · q quit"
	if viewHints != "" {
		return m.styles.Help.Render(" " + viewHints + "  |  " + global)
	}
	return m.styles.Help.Render(" " + global)
}

// placeOverlay centers a modal over a dotted scrim (lipgloss cannot compose
// true overlays; a patterned backdrop reads as intentional instead of void).
func (m cliModel) placeOverlay(modal string) string {
	return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, modal,
		lipgloss.WithWhitespaceChars("░"),
		lipgloss.WithWhitespaceForeground(m.styles.Muted.GetForeground()))
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

func startCLI(refresh time.Duration) {
	reconcileCommit()
	m := initialModel()
	m.refreshInterval = refresh
	p := tea.NewProgram(m, tea.WithAltScreen(), tea.WithMouseAllMotion())
	if _, err := p.Run(); err != nil {
		fmt.Printf("Error starting CLI: %v", err)
		os.Exit(1)
	}
}
