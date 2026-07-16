package main

// System view: per-interface throughput sparklines, flags and error counters.
// Every map access is defensive — a missing key degrades, never panics.

import (
	"fmt"
	"strings"

	"github.com/NimbleMarkets/ntcharts/sparkline"
)

func (m *cliModel) updateSystemData() {
	for _, iface := range asIfaceList(m.ifStats, "ifaces") {
		name := asStr(iface, "name")
		if name == "" {
			continue
		}
		if _, ok := m.rxSparklines[name]; !ok {
			m.rxSparklines[name] = sparkline.New(20, 1)
			m.txSparklines[name] = sparkline.New(20, 1)
		}
		if rx := asF64s(iface, "rx_bps"); rx != nil {
			sl := m.rxSparklines[name]
			sl.Clear()
			sl.PushAll(rx)
			sl.Draw()
			m.rxSparklines[name] = sl
		}
		if tx := asF64s(iface, "tx_bps"); tx != nil {
			sl := m.txSparklines[name]
			sl.Clear()
			sl.PushAll(tx)
			sl.Draw()
			m.txSparklines[name] = sl
		}
	}
}

func (m cliModel) renderSystem() string {
	var sb strings.Builder
	for _, iface := range asIfaceList(m.ifStats, "ifaces") {
		name := asStr(iface, "name")
		if name == "" {
			continue
		}
		up := m.styles.DropVerdict.Render("DOWN")
		if asBool(iface, "up") {
			up = m.styles.AcceptVerdict.Render("UP")
		}

		flags := ""
		if asBool(iface, "veth") {
			flags += " [veth]"
		}
		if asBool(iface, "bridge") {
			flags += " [bridge]"
		}

		sb.WriteString(fmt.Sprintf("%-10s [%s] Speed: %d Mbps %s\n", name, up, asInt(iface, "speed_mbps"), flags))
		sb.WriteString("  RX: " + m.rxSparklines[name].View() + " " + formatBps(asF64s(iface, "rx_bps")))
		if errs, ok := iface["errors"].(map[string]uint64); ok && errs["rx_errs"] > 0 {
			sb.WriteString(m.styles.DropVerdict.Render(fmt.Sprintf(" (Errs: %d)", errs["rx_errs"])))
		}
		sb.WriteString("\n")

		sb.WriteString("  TX: " + m.txSparklines[name].View() + " " + formatBps(asF64s(iface, "tx_bps")))
		if errs, ok := iface["errors"].(map[string]uint64); ok && errs["tx_errs"] > 0 {
			sb.WriteString(m.styles.DropVerdict.Render(fmt.Sprintf(" (Errs: %d)", errs["tx_errs"])))
		}
		sb.WriteString("\n\n")
	}
	if sb.Len() == 0 {
		return "No interface data."
	}
	return sb.String()
}
