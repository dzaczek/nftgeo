package main

// Objects → Reference subview: an editable whitelist (the same
// draft→validate→apply pipeline as everything else, via saveWhitelistDraft),
// plus read-only abuse feeds and nft set sizes. Toggled with 'w' from the
// Objects tree.

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

func formatAbsoluteLocal(epochSeconds int64) string {
	t := time.Unix(epochSeconds, 0).Local()
	return t.Format("2006-01-02 15:04:05")
}

func formatRelativeAge(seconds int64) string {
	if seconds < 0 {
		return "just now"
	}
	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh ago", days, hours)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm ago", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm ago", minutes)
	}
	return "< 1m ago"
}

func (m cliModel) getHealthMap() map[string]interface{} {
	if m.status == nil {
		return nil
	}
	h, _ := m.status["health"].(map[string]interface{})
	return h
}

func (m cliModel) getStatusMap() map[string]interface{} {
	h := m.getHealthMap()
	if h == nil {
		return nil
	}
	st, _ := h["status"].(map[string]interface{})
	return st
}

func (m cliModel) getGeoFreshness() (cadence, successTime, age, state string) {
	h := m.getHealthMap()
	st := m.getStatusMap()

	cacheHours := 20
	if h != nil {
		if val, ok := h["zoneCacheHours"].(string); ok && val != "" {
			if parsed, err := strconv.Atoi(val); err == nil {
				cacheHours = parsed
			}
		}
	}
	cadence = fmt.Sprintf("Twice daily / Cache: %dh", cacheHours)

	geoActive := false
	if h != nil {
		geoActive, _ = h["geoActive"].(bool)
	}

	if !geoActive {
		return cadence, "—", "—", "Disabled (no geo rules configured)"
	}

	if st == nil {
		return cadence, "—", "—", "Never fetched"
	}

	geo, _ := st["geo"].(map[string]interface{})
	if geo == nil {
		return cadence, "—", "—", "Never fetched"
	}

	fetchedAtVal := geo["fetched_at"]
	if fetchedAtVal == nil {
		return cadence, "—", "—", "Never fetched"
	}

	var fetchedAt int64
	switch v := fetchedAtVal.(type) {
	case float64:
		fetchedAt = int64(v)
	case int64:
		fetchedAt = v
	case int:
		fetchedAt = int64(v)
	}

	if fetchedAt == 0 {
		return cadence, "—", "—", "Never fetched"
	}

	nowSecs := time.Now().Unix()
	successTime = formatAbsoluteLocal(fetchedAt)
	ageSecs := nowSecs - fetchedAt
	age = formatRelativeAge(ageSecs)

	var runTs int64
	if runTsVal, ok := st["timestamp"]; ok {
		switch r := runTsVal.(type) {
		case float64:
			runTs = int64(r)
		case int64:
			runTs = r
		case int:
			runTs = int64(r)
		}
	}
	if runTs == 0 {
		runTs = nowSecs
	}

	isStale := ageSecs > int64(cacheHours*3600)
	isFresh := (runTs - fetchedAt) <= 60
	hasFail := false
	if st != nil {
		if warnsVal, ok := st["warnings"]; ok {
			if list, ok := warnsVal.([]interface{}); ok {
				for _, w := range list {
					s, _ := w.(string)
					if strings.Contains(s, "Zone refresh failed") || strings.Contains(s, "Zone unavailable") {
						hasFail = true
						break
					}
				}
			} else if list, ok := warnsVal.([]string); ok {
				for _, s := range list {
					if strings.Contains(s, "Zone refresh failed") || strings.Contains(s, "Zone unavailable") {
						hasFail = true
						break
					}
				}
			}
		}
	}

	if hasFail {
		state = "Stale (using cache after failure)"
	} else if isFresh {
		state = "Freshly downloaded"
	} else if isStale {
		state = "Stale"
	} else {
		state = "OK"
	}

	return cadence, successTime, age, state
}

func (m cliModel) getAbuseFreshness() (cadence, successTime, age, state string) {
	h := m.getHealthMap()
	st := m.getStatusMap()

	retentionDays := 30
	if h != nil {
		if val, ok := h["abuseRetentionDays"].(string); ok && val != "" {
			if parsed, err := strconv.Atoi(val); err == nil {
				retentionDays = parsed
			}
		}
	}
	cadence = fmt.Sprintf("Twice daily / Retention: %dd", retentionDays)

	if st == nil {
		return cadence, "—", "—", "Never fetched"
	}

	abuse, _ := st["abuse"].(map[string]interface{})
	if abuse == nil {
		return cadence, "—", "—", "Never fetched"
	}

	ruleActive, _ := abuse["rule_active"].(bool)
	apiKeyPresent, _ := abuse["api_key_present"].(bool)

	customFeedsCount := 0
	if h != nil {
		var feedsList []map[string]interface{}
		if raw, ok := h["feeds"]; ok {
			if list, ok := raw.([]map[string]interface{}); ok {
				feedsList = list
			} else if list, ok := raw.([]interface{}); ok {
				for _, item := range list {
					if m, ok := item.(map[string]interface{}); ok {
						feedsList = append(feedsList, m)
					}
				}
			}
		}
		for _, f := range feedsList {
			if asStr(f, "name") != "AbuseIPDB" {
				customFeedsCount++
			}
		}
	}
	isAbuseConfigured := apiKeyPresent || customFeedsCount > 0

	if !ruleActive {
		return cadence, "—", "—", "Disabled (no active rule targets \"abuse\")"
	}

	if !isAbuseConfigured {
		return cadence, "—", "—", "Not configured (no API key and no custom feeds)"
	}

	fetchedAtVal := abuse["fetched_at"]
	if fetchedAtVal == nil {
		return cadence, "—", "—", "Never fetched"
	}

	var fetchedAt int64
	switch v := fetchedAtVal.(type) {
	case float64:
		fetchedAt = int64(v)
	case int64:
		fetchedAt = v
	case int:
		fetchedAt = int64(v)
	}

	if fetchedAt == 0 {
		return cadence, "—", "—", "Never fetched"
	}

	nowSecs := time.Now().Unix()
	successTime = formatAbsoluteLocal(fetchedAt)
	ageSecs := nowSecs - fetchedAt
	age = formatRelativeAge(ageSecs)

	var runTs int64
	if runTsVal, ok := st["timestamp"]; ok {
		switch r := runTsVal.(type) {
		case float64:
			runTs = int64(r)
		case int64:
			runTs = r
		case int:
			runTs = int64(r)
		}
	}
	if runTs == 0 {
		runTs = nowSecs
	}

	isStale := ageSecs > (26 * 3600) // 26h because run twice daily
	isFresh := (runTs - fetchedAt) <= 60
	hasFail := false
	if warnsVal, ok := st["warnings"]; ok {
		if list, ok := warnsVal.([]interface{}); ok {
			for _, w := range list {
				s, _ := w.(string)
				if strings.Contains(s, "AbuseIPDB download failed") || strings.Contains(s, "download failed") || strings.Contains(s, "using cached copy") {
					hasFail = true
					break
				}
			}
		} else if list, ok := warnsVal.([]string); ok {
			for _, s := range list {
				if strings.Contains(s, "AbuseIPDB download failed") || strings.Contains(s, "download failed") || strings.Contains(s, "using cached copy") {
					hasFail = true
					break
				}
			}
		}
	}

	if hasFail {
		state = "Stale (using cache after failure)"
	} else if isFresh {
		state = "Freshly downloaded"
	} else if isStale {
		state = "Stale"
	} else {
		state = "OK"
	}

	return cadence, successTime, age, state
}

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
			return m, fetchDataCmd(m.logLimit)
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
		return m, fetchDataCmd(m.logLimit)
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

	// Left column: Whitelist editor
	var leftCol strings.Builder
	leftCol.WriteString(m.styles.PanelTitle.Render(fmt.Sprintf("Whitelist (%d)", len(m.wlEntries))) + "\n")
	if m.refAddMode {
		leftCol.WriteString("  " + m.styles.Accent.Render("+ ") + m.objInput.View() + "\n")
	}
	if len(m.wlEntries) == 0 && !m.refAddMode {
		leftCol.WriteString(m.styles.Muted.Render("  (empty — press a to add an IP or CIDR)") + "\n")
	}
	for i, e := range m.wlEntries {
		cursor := "  "
		line := e
		if i == m.refSel && !m.refAddMode {
			cursor = m.styles.Accent.Render("▶ ")
			line = m.styles.Accent.Copy().Bold(true).Render(e)
		}
		leftCol.WriteString(cursor + line + "\n")
	}
	if len(m.wlHosts) > 0 {
		leftCol.WriteString("\n" + m.styles.Muted.Render(fmt.Sprintf("  hosts: %s", strings.Join(m.wlHosts, ", "))) + "\n")
	}

	// Right column: Data Freshness Summary, Abuse Feeds, nft sets
	var rightCol strings.Builder

	// Geolocation Data status
	gCadence, gTime, gAge, gState := m.getGeoFreshness()
	rightCol.WriteString(m.styles.PanelTitle.Render("Geolocation Data") + "\n")
	rightCol.WriteString(fmt.Sprintf("  Cadence: %s\n", gCadence))
	rightCol.WriteString(fmt.Sprintf("  Success: %s\n", gTime))
	rightCol.WriteString(fmt.Sprintf("  Age:     %s\n", gAge))
	rightCol.WriteString(fmt.Sprintf("  State:   %s\n\n", gState))

	// Bad-IP / Abuse Data status
	aCadence, aTime, aAge, aState := m.getAbuseFreshness()
	rightCol.WriteString(m.styles.PanelTitle.Render("Bad-IP / Abuse Data") + "\n")
	rightCol.WriteString(fmt.Sprintf("  Cadence: %s\n", aCadence))
	rightCol.WriteString(fmt.Sprintf("  Success: %s\n", aTime))
	rightCol.WriteString(fmt.Sprintf("  Age:     %s\n", aAge))
	rightCol.WriteString(fmt.Sprintf("  State:   %s\n\n", aState))

	// Abuse feeds
	rightCol.WriteString(m.styles.PanelTitle.Render("Abuse feeds") + "\n")
	if len(m.feeds) == 0 {
		rightCol.WriteString(m.styles.Muted.Render("  none") + "\n")
	}
	for _, f := range m.feeds {
		mark := m.styles.AcceptVerdict.Render("●")
		if !asBool(f, "fresh") {
			mark = m.styles.Warning.Render("●")
		}

		// Let's use modTime to render detailed age and absolute time
		var feedAge, feedAbs string
		if modVal, ok := f["modTime"]; ok {
			var modTime int64
			switch mv := modVal.(type) {
			case float64:
				modTime = int64(mv)
			case int64:
				modTime = mv
			case int:
				modTime = int64(mv)
			}
			if modTime > 0 {
				feedAge = formatRelativeAge(time.Now().Unix() - modTime)
				feedAbs = formatAbsoluteLocal(modTime)
			}
		}
		if feedAge == "" {
			feedAge = fmt.Sprintf("%dh ago", asInt(f, "ageHours"))
			feedAbs = "—"
		}

		rightCol.WriteString(fmt.Sprintf("  %s %-12s %6s  %s (%s)\n",
			mark, clip(asStr(f, "name"), 12), formatCount(asInt(f, "count")), feedAge, feedAbs))
	}
	rightCol.WriteString("\n")

	// nft sets
	rightCol.WriteString(m.styles.PanelTitle.Render("nft sets") + "\n")
	if len(m.setsList) == 0 {
		rightCol.WriteString(m.styles.Muted.Render("  none") + "\n")
	}
	for _, s := range m.setsList {
		rightCol.WriteString(fmt.Sprintf("  %-18s %8s\n", clip(s.Name, 18), formatCount(s.Count)))
	}

	colW := (m.viewWidth() - 2) / 2
	if colW < 40 {
		colW = 40
	}
	cols := joinColumns(colW, leftCol.String(), rightCol.String())

	b.WriteString("\n" + cols)
	return b.String()
}
