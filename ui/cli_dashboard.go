package main

// Dashboard view: KPI tiles, the 24h braille drops timeline, alerts, the
// abuse-load gauge and four top-N panels (countries in/out, ports, source
// IPs with per-IP mini-histograms). The top-N panels are plain text tables
// with inline block bars — the previous ntcharts barcharts collapsed to
// empty bars whenever one value dominated the autoscale.

import (
	"fmt"
	"sort"
	"time"

	"github.com/NimbleMarkets/ntcharts/canvas"
	"github.com/NimbleMarkets/ntcharts/linechart"
	"github.com/charmbracelet/lipgloss"
)

func (m *cliModel) updateDashboardData() {
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
}

// kvCount is one row of a top-N panel.
type kvCount struct {
	label string
	n     int
}

// sortedCounts turns a count map into a descending top-N list.
func sortedCounts(counts map[string]int, limit int) []kvCount {
	out := make([]kvCount, 0, len(counts))
	for k, v := range counts {
		out = append(out, kvCount{k, v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].n != out[j].n {
			return out[i].n > out[j].n
		}
		return out[i].label < out[j].label
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// topPanel renders a titled "label count bar" table. Bars scale to the
// panel's own maximum, so every row shows a visible proportion.
func (m cliModel) topPanel(title string, rows []kvCount, width int, barStyle lipgloss.Style) string {
	out := m.styles.PanelTitle.Render(title) + "\n"
	if len(rows) == 0 {
		return out + m.styles.Muted.Render("  no data")
	}
	maxN := rows[0].n
	if maxN < 1 {
		maxN = 1
	}
	labelW, countW := 8, 7
	barW := width - labelW - countW - 4
	if barW < 5 {
		barW = 5
	}
	for _, r := range rows {
		w := r.n * barW / maxN
		if w < 1 {
			w = 1
		}
		bar := barStyle.Render(repeatRune('▇', w))
		out += fmt.Sprintf("  %-*s %*s %s\n", labelW, clip(r.label, labelW), countW, formatCount(r.n), bar)
	}
	return out
}

// miniHistogram maps per-bucket counts onto block characters (▁▂▃▄▅▆▇█).
func miniHistogram(buckets []int) string {
	if len(buckets) == 0 {
		return ""
	}
	ramp := []rune(" ▁▂▃▄▅▆▇█")
	maxN := 1
	for _, b := range buckets {
		if b > maxN {
			maxN = b
		}
	}
	out := make([]rune, len(buckets))
	for i, b := range buckets {
		idx := b * (len(ramp) - 1) / maxN
		out[i] = ramp[idx]
	}
	return string(out)
}

// topIPsPanel renders the top source IPs with hit counts and a 24h
// mini-histogram per IP (the web's #topip table, in text form).
func (m cliModel) topIPsPanel(width int) string {
	out := m.styles.PanelTitle.Render("Top Source IPs (24h)") + "\n"
	if len(m.topIPs) == 0 {
		return out + m.styles.Muted.Render("  no data")
	}
	for _, ip := range m.topIPs {
		last := ""
		if ts := asInt(ip, "last"); ts > 0 {
			last = time.Unix(int64(ts), 0).Format("15:04")
		}
		hist := ""
		if b, ok := ip["buckets"].([]int); ok {
			hist = m.styles.Accent.Render(miniHistogram(b))
		}
		out += fmt.Sprintf("  %-16s %7s  %s  %-3s %s\n",
			clip(asStr(ip, "ip"), 16), formatCount(asInt(ip, "hits")), hist, asStr(ip, "cc"), m.styles.Muted.Render(last))
	}
	return out
}

func formatCount(n int) string {
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 10000 {
		return fmt.Sprintf("%.1fk", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

func clip(s string, w int) string {
	if len(s) <= w {
		return s
	}
	if w <= 1 {
		return s[:w]
	}
	return s[:w-1] + "…"
}

func repeatRune(r rune, n int) string {
	out := make([]rune, n)
	for i := range out {
		out[i] = r
	}
	return string(out)
}

func (m cliModel) renderKPI(label, value string) string {
	return m.styles.Kpi.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			m.styles.KpiLabel.Render(label),
			m.styles.KpiValue.Render(value),
		),
	)
}

// renderAlerts renders the buildAlerts strip (crit red, warn yellow).
func (m cliModel) renderAlerts() string {
	if len(m.alerts) == 0 {
		return ""
	}
	out := ""
	for _, a := range m.alerts {
		line := "▲ " + a.Msg
		if a.Level == "crit" {
			out += m.styles.StatusErr.Render(line) + "\n"
		} else {
			out += m.styles.Warning.Render(line) + "\n"
		}
	}
	return out
}

// renderAbuseLoad shows feed-loading progress while the engine ingests lists.
func (m cliModel) renderAbuseLoad() string {
	if !asBool(m.abuseLoad, "active") {
		return ""
	}
	loaded, total := asInt(m.abuseLoad, "loaded"), asInt(m.abuseLoad, "total")
	pct := asInt(m.abuseLoad, "pct")
	barW := 20
	fill := pct * barW / 100
	if fill > barW {
		fill = barW
	}
	bar := repeatRune('█', fill) + repeatRune('░', barW-fill)
	return m.styles.Warning.Render(fmt.Sprintf("abuse feeds loading: %s %d%% (%s/%s)",
		bar, pct, formatCount(loaded), formatCount(total))) + "\n"
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
	for _, iface := range asIfaceList(m.ifStats, "ifaces") {
		if rx := asF64s(iface, "rx_bps"); len(rx) > 0 {
			rxTotal += rx[len(rx)-1]
		}
		if tx := asF64s(iface, "tx_bps"); len(tx) > 0 {
			txTotal += tx[len(tx)-1]
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

	vw := m.viewWidth()
	panelW := (vw - 4) / 3
	if panelW < 24 {
		panelW = 24
	}
	limit := 5
	if m.height > 44 {
		limit = 8
	}

	topRow := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.NewStyle().Width(panelW).Render(m.topPanel("Top Countries In", sortedCounts(m.drops.IngressByCC, limit), panelW, m.styles.DropVerdict)),
		lipgloss.NewStyle().Width(panelW).Render(m.topPanel("Top Countries Out", sortedCounts(m.drops.EgressByCC, limit), panelW, m.styles.DropVerdict)),
		lipgloss.NewStyle().Width(panelW).Render(m.topPanel("Top Ports", sortedCounts(m.drops.TopPorts, limit), panelW, m.styles.Accent)),
	)

	sections := []string{}
	if a := m.renderAlerts(); a != "" {
		sections = append(sections, a)
	}
	if a := m.renderAbuseLoad(); a != "" {
		sections = append(sections, a)
	}
	sections = append(sections,
		kpiRow, "",
		m.styles.PanelTitle.Render("Drops over 24h"),
		m.dropsChart.View(), "",
		topRow, "",
		m.topIPsPanel(vw),
	)

	return lipgloss.JoinVertical(lipgloss.Left, sections...)
}

func (m cliModel) getConntrack() string {
	if ct, ok := m.ifStats["conntrack"].(map[string]uint64); ok {
		return fmt.Sprintf("%d / %d", ct["count"], ct["max"])
	}
	return "n/a"
}
