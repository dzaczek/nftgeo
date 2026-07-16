package main

// Dashboard view: KPI tiles, the 24h braille drops timeline and the top-N
// charts.

import (
	"fmt"
	"sort"

	"github.com/NimbleMarkets/ntcharts/barchart"
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

	p := cliDarkPalette
	if !m.darkTheme {
		p = cliLightPalette
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
			Values: []barchart.BarValue{{Value: float64(m.drops.IngressByCC[ccKeys[i]]), Style: lipgloss.NewStyle().Foreground(p.Drop)}},
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
			Values: []barchart.BarValue{{Value: float64(m.drops.TopPorts[portKeys[i]]), Style: lipgloss.NewStyle().Foreground(p.Accent)}},
		})
	}
	m.topPortsChart.Draw()
}

func (m cliModel) renderKPI(label, value string) string {
	return m.styles.Kpi.Render(
		lipgloss.JoinVertical(lipgloss.Left,
			m.styles.KpiLabel.Render(label),
			m.styles.KpiValue.Render(value),
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

	chartTitle := m.styles.PanelTitle.Render("Drops over 24h")
	chart := m.dropsChart.View()

	bottomCharts := lipgloss.JoinHorizontal(lipgloss.Top,
		lipgloss.JoinVertical(lipgloss.Left, m.styles.PanelTitle.Render("Top Countries"), m.ingressChart.View()),
		lipgloss.JoinVertical(lipgloss.Left, m.styles.PanelTitle.Render("Top Ports"), m.topPortsChart.View()),
	)

	return lipgloss.JoinVertical(lipgloss.Left, kpiRow, "", chartTitle, chart, "", bottomCharts)
}

func (m cliModel) getConntrack() string {
	if ct, ok := m.ifStats["conntrack"].(map[string]uint64); ok {
		return fmt.Sprintf("%d / %d", ct["count"], ct["max"])
	}
	return "n/a"
}
