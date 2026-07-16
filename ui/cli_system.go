package main

// System view: per-interface throughput sparklines with flags, a since-boot
// error-counter table, and a conntrack usage bar. Scrollable (j/k / arrows /
// pgup-pgdn) so many interfaces don't overflow. Every map access is defensive
// — a missing or oddly-typed key degrades, never panics.

import (
	"fmt"
	"strings"

	"github.com/NimbleMarkets/ntcharts/sparkline"
)

const systemHints = "↑↓/pgup/pgdn scroll"

// errCounterKeys lists the per-interface error columns in display order.
var errCounterKeys = []struct{ key, label string }{
	{"rx_errs", "rxErr"}, {"rx_drop", "rxDrop"}, {"rx_fifo", "rxFifo"}, {"rx_frame", "rxFrame"},
	{"tx_errs", "txErr"}, {"tx_drop", "txDrop"}, {"tx_fifo", "txFifo"}, {"tx_colls", "colls"}, {"tx_carrier", "carrier"},
}

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
	m.sysVP.SetContent(m.systemBody())
}

// u64map reads a map[string]uint64 (the errors/errors_total shapes) safely.
func u64map(m map[string]interface{}, k string) map[string]uint64 {
	if m == nil {
		return nil
	}
	v, _ := m[k].(map[string]uint64)
	return v
}

// conntrackBar renders the conntrack count/max as a usage bar.
func (m cliModel) conntrackBar() string {
	ct, ok := m.ifStats["conntrack"].(map[string]uint64)
	if !ok {
		return ""
	}
	count, max := ct["count"], ct["max"]
	pct := 0
	if max > 0 {
		pct = int(count * 100 / max)
	}
	barW := 24
	fill := pct * barW / 100
	if fill > barW {
		fill = barW
	}
	style := m.styles.AcceptVerdict
	if pct >= 80 {
		style = m.styles.DropVerdict
	} else if pct >= 50 {
		style = m.styles.Warning
	}
	bar := style.Render(repeatRune('█', fill)) + m.styles.Muted.Render(repeatRune('░', barW-fill))
	return fmt.Sprintf("%s %s %d%% (%s / %s)\n\n",
		m.styles.PanelTitle.Render("Conntrack"), bar, pct, formatCount(int(count)), formatCount(int(max)))
}

// systemBody builds the full (scrollable) System content.
func (m cliModel) systemBody() string {
	var sb strings.Builder

	sb.WriteString(m.conntrackBar())

	ifaces := asIfaceList(m.ifStats, "ifaces")
	for _, iface := range ifaces {
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
		sb.WriteString("  RX: " + m.rxSparklines[name].View() + " " + formatBps(asF64s(iface, "rx_bps")) + "\n")
		sb.WriteString("  TX: " + m.txSparklines[name].View() + " " + formatBps(asF64s(iface, "tx_bps")) + "\n")
	}

	// Since-boot error table across interfaces (only columns with any errors).
	sb.WriteString("\n" + m.styles.PanelTitle.Render("Interface errors (since boot)") + "\n")
	active := activeErrColumns(ifaces)
	if len(active) == 0 {
		sb.WriteString(m.styles.Muted.Render("  none"))
		return sb.String()
	}
	header := fmt.Sprintf("  %-10s", "iface")
	for _, c := range active {
		header += fmt.Sprintf(" %8s", c.label)
	}
	sb.WriteString(m.styles.Muted.Render(header) + "\n")
	for _, iface := range ifaces {
		name := asStr(iface, "name")
		if name == "" {
			continue
		}
		tot := u64map(iface, "errors_total")
		line := fmt.Sprintf("  %-10s", clip(name, 10))
		for _, c := range active {
			v := tot[c.key]
			cell := fmt.Sprintf("%8d", v)
			if v > 0 {
				cell = m.styles.DropVerdict.Render(cell)
			}
			line += " " + cell
		}
		sb.WriteString(line + "\n")
	}
	return sb.String()
}

// activeErrColumns returns the error columns that are non-zero on any iface,
// so the table stays narrow on healthy hosts.
func activeErrColumns(ifaces []map[string]interface{}) []struct{ key, label string } {
	seen := map[string]bool{}
	for _, iface := range ifaces {
		tot := u64map(iface, "errors_total")
		for k, v := range tot {
			if v > 0 {
				seen[k] = true
			}
		}
	}
	var out []struct{ key, label string }
	for _, c := range errCounterKeys { // errCounterKeys is the display order
		if seen[c.key] {
			out = append(out, c)
		}
	}
	return out
}

func (m cliModel) renderSystem() string {
	if len(asIfaceList(m.ifStats, "ifaces")) == 0 {
		return "No interface data."
	}
	return m.sysVP.View()
}
