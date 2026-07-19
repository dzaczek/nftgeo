package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestFormatRelativeAge(t *testing.T) {
	tests := []struct {
		secs int64
		want string
	}{
		{-10, "just now"},
		{0, "< 1m ago"},
		{30, "< 1m ago"},
		{60, "1m ago"},
		{119, "1m ago"},
		{120, "2m ago"},
		{3599, "59m ago"},
		{3600, "1h 0m ago"},
		{8050, "2h 14m ago"}, // 2h 14m 10s
		{86399, "23h 59m ago"},
		{86400, "1d 0h ago"},
		{187500, "2d 4h ago"}, // 2d 4h 5m
	}

	for _, tt := range tests {
		got := formatRelativeAge(tt.secs)
		if got != tt.want {
			t.Errorf("formatRelativeAge(%d) = %q, want %q", tt.secs, got, tt.want)
		}
	}
}

func TestFormatAbsoluteLocal(t *testing.T) {
	now := time.Now().Unix()
	got := formatAbsoluteLocal(now)
	if len(got) != 19 {
		t.Errorf("formatAbsoluteLocal(%d) = %q, want length 19 (YYYY-MM-DD HH:MM:SS)", now, got)
	}
	parts := strings.Split(got, " ")
	if len(parts) != 2 {
		t.Fatalf("expected space-separated date and time, got %q", got)
	}
	dateParts := strings.Split(parts[0], "-")
	if len(dateParts) != 3 || len(dateParts[0]) != 4 {
		t.Errorf("expected YYYY-MM-DD, got %q", parts[0])
	}
	timeParts := strings.Split(parts[1], ":")
	if len(timeParts) != 3 {
		t.Errorf("expected HH:MM:SS, got %q", parts[1])
	}
}

func TestGetGeoFreshnessStates(t *testing.T) {
	m := cliModel{}

	// Case 1: geoActive is false (disabled)
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"geoActive":      false,
			"zoneCacheHours": "20",
		},
	}
	_, _, _, state := m.getGeoFreshness()
	if !strings.Contains(state, "Disabled") {
		t.Errorf("expected disabled state, got %q", state)
	}

	// Case 2: geoActive is true but status map is nil (Never fetched)
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"geoActive":      true,
			"zoneCacheHours": "20",
		},
	}
	_, _, _, state = m.getGeoFreshness()
	if state != "Never fetched" {
		t.Errorf("expected Never fetched state, got %q", state)
	}

	// Case 3: geoActive is true, status has geo but fetched_at is 0
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"geoActive": true,
			"status": map[string]interface{}{
				"geo": map[string]interface{}{
					"fetched_at": float64(0),
				},
			},
		},
	}
	_, _, _, state = m.getGeoFreshness()
	if state != "Never fetched" {
		t.Errorf("expected Never fetched state with 0 timestamp, got %q", state)
	}

	// Case 4: freshly downloaded (OK - within 60s of run time)
	now := time.Now().Unix()
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"geoActive": true,
			"status": map[string]interface{}{
				"timestamp": float64(now),
				"geo": map[string]interface{}{
					"fetched_at": float64(now - 10),
				},
			},
		},
	}
	_, _, _, state = m.getGeoFreshness()
	if state != "OK (freshly downloaded)" {
		t.Errorf("expected OK (freshly downloaded), got %q", state)
	}

	// Case 5: using cached data normally (within ZONE_CACHE_HOURS, but older than 60s run time)
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"geoActive":      true,
			"zoneCacheHours": "20",
			"status": map[string]interface{}{
				"timestamp": float64(now),
				"geo": map[string]interface{}{
					"fetched_at": float64(now - 1800), // 30 minutes ago
				},
			},
		},
	}
	_, _, _, state = m.getGeoFreshness()
	if state != "OK (using cached data)" {
		t.Errorf("expected OK (using cached data), got %q", state)
	}

	// Case 6: stale (reused expired cache after failure)
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"geoActive":      true,
			"zoneCacheHours": "2",
			"status": map[string]interface{}{
				"timestamp": float64(now),
				"geo": map[string]interface{}{
					"fetched_at": float64(now - 3*3600), // 3 hours ago (cache is 2h)
				},
			},
		},
	}
	_, _, _, state = m.getGeoFreshness()
	if state != "Stale (using cache after failure)" {
		t.Errorf("expected Stale (using cache after failure), got %q", state)
	}
}

func TestGetAbuseFreshnessStates(t *testing.T) {
	m := cliModel{}

	// Case 1: rule_active is false (disabled)
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"status": map[string]interface{}{
				"abuse": map[string]interface{}{
					"rule_active": false,
				},
			},
		},
	}
	_, _, _, state := m.getAbuseFreshness()
	if !strings.Contains(state, "Disabled") {
		t.Errorf("expected disabled state, got %q", state)
	}

	// Case 2: rule_active is true but not configured (no key and no feeds)
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"feeds": []interface{}{},
			"status": map[string]interface{}{
				"abuse": map[string]interface{}{
					"rule_active":     true,
					"api_key_present": false,
					"fetched_at":      nil,
				},
			},
		},
	}
	_, _, _, state = m.getAbuseFreshness()
	if !strings.Contains(state, "Not configured") {
		t.Errorf("expected not configured state, got %q", state)
	}

	// Case 3: rule_active is true, configured (api_key_present = true), but fetched_at is nil
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"status": map[string]interface{}{
				"abuse": map[string]interface{}{
					"rule_active":     true,
					"api_key_present": true,
					"fetched_at":      nil,
				},
			},
		},
	}
	_, _, _, state = m.getAbuseFreshness()
	if state != "Never fetched" {
		t.Errorf("expected Never fetched state, got %q", state)
	}

	// Case 4: OK (freshly downloaded)
	now := time.Now().Unix()
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"status": map[string]interface{}{
				"timestamp": float64(now),
				"abuse": map[string]interface{}{
					"rule_active":     true,
					"api_key_present": true,
					"fetched_at":      float64(now - 10),
				},
			},
		},
	}
	_, _, _, state = m.getAbuseFreshness()
	if state != "OK (freshly downloaded)" {
		t.Errorf("expected OK (freshly downloaded), got %q", state)
	}

	// Case 5: OK (using cached data)
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"status": map[string]interface{}{
				"timestamp": float64(now),
				"abuse": map[string]interface{}{
					"rule_active":     true,
					"api_key_present": true,
					"fetched_at":      float64(now - 1800), // 30 mins ago
				},
			},
		},
	}
	_, _, _, state = m.getAbuseFreshness()
	if state != "OK (using cached data)" {
		t.Errorf("expected OK (using cached data), got %q", state)
	}

	// Case 6: Stale
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"status": map[string]interface{}{
				"timestamp": float64(now),
				"abuse": map[string]interface{}{
					"rule_active":     true,
					"api_key_present": true,
					"fetched_at":      float64(now - 28*3600), // 28 hours ago
				},
			},
		},
	}
	_, _, _, state = m.getAbuseFreshness()
	if state != "Stale (using cache after failure)" {
		t.Errorf("expected Stale (using cache after failure), got %q", state)
	}
}

func TestGetAbuseFreshnessCustomFeedsOnly(t *testing.T) {
	m := cliModel{}

	// Verify that if we have custom feeds but no api key (api_key_present = false),
	// it is still considered configured (not showing "Not configured").
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"feeds": []map[string]interface{}{
				{"name": "SomeCustomFeed", "count": 100},
			},
			"status": map[string]interface{}{
				"abuse": map[string]interface{}{
					"rule_active":     true,
					"api_key_present": false,
					"fetched_at":      float64(time.Now().Unix() - 100),
				},
			},
		},
	}

	_, _, _, state := m.getAbuseFreshness()
	if strings.Contains(state, "Not configured") {
		t.Errorf("expected custom feeds to satisfy configured state, but got state %q", state)
	}

	// Test feeds list as []interface{}
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"feeds": []interface{}{
				map[string]interface{}{"name": "SomeCustomFeed", "count": 100},
			},
			"status": map[string]interface{}{
				"abuse": map[string]interface{}{
					"rule_active":     true,
					"api_key_present": false,
					"fetched_at":      float64(time.Now().Unix() - 100),
				},
			},
		},
	}

	_, _, _, state = m.getAbuseFreshness()
	if strings.Contains(state, "Not configured") {
		t.Errorf("expected []interface{} custom feeds list to satisfy configured state, but got state %q", state)
	}
}

func TestExplicitStaleCacheAfterFailure(t *testing.T) {
	m := cliModel{}
	now := time.Now().Unix()

	// Verify that if warnings contain a failure, it explicitly signals stale cache fallback, even if within time window
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"geoActive":      true,
			"zoneCacheHours": "20",
			"status": map[string]interface{}{
				"timestamp": float64(now),
				"warnings": []interface{}{
					"Zone refresh failed for 'de', using cached copy.",
				},
				"geo": map[string]interface{}{
					"fetched_at": float64(now - 100),
				},
			},
		},
	}

	_, _, _, state := m.getGeoFreshness()
	if state != "Stale (using cache after failure)" {
		t.Errorf("expected explicit stale/cache fallback state from warnings, got %q", state)
	}

	// Abuse fail warning
	m.status = map[string]interface{}{
		"health": map[string]interface{}{
			"status": map[string]interface{}{
				"timestamp": float64(now),
				"warnings": []interface{}{
					"AbuseIPDB download failed; using retained state from /var/lib/nftgeo/abuseipdb.tsv.",
				},
				"abuse": map[string]interface{}{
					"rule_active":     true,
					"api_key_present": true,
					"fetched_at":      float64(now - 100),
				},
			},
		},
	}

	_, _, _, state = m.getAbuseFreshness()
	if state != "Stale (using cache after failure)" {
		t.Errorf("expected explicit stale state from abuse warning, got %q", state)
	}
}

func TestIsGeoActiveCommaSeparatedAndCaching(t *testing.T) {
	dir := t.TempDir()
	cf := filepath.Join(dir, "config")
	rf := filepath.Join(dir, "rules.conf")
	ol := filepath.Join(dir, "objects.conf")
	wl := filepath.Join(dir, "whitelist.conf")
	wlh := filepath.Join(dir, "whitelist-hosts.conf")
	sentinelFile := filepath.Join(dir, ".pending-confirm")
	drDir := filepath.Join(dir, "drafts")

	// Mock system paths
	oldConfig, oldRules, oldObjLive, oldDraftDir, oldSentinelFile, oldWhitelistFile, oldWhitelistHostsFile := configFile, rulesFile, objLiveFile, draftDir, sentinel, whitelistFile, whitelistHostsFile
	configFile, rulesFile, objLiveFile, draftDir, sentinel, whitelistFile, whitelistHostsFile = cf, rf, ol, drDir, sentinelFile, wl, wlh
	defer func() {
		configFile, rulesFile, objLiveFile, draftDir, sentinel, whitelistFile, whitelistHostsFile = oldConfig, oldRules, oldObjLive, oldDraftDir, oldSentinelFile, oldWhitelistFile, oldWhitelistHostsFile
	}()

	os.MkdirAll(drDir, 0755)

	// Write rules with comma-separated targets like "pl,de"
	if err := os.WriteFile(rf, []byte("allow in tcp 80 pl,de\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Verify it calculates to true
	geoActive := calculateGeoActive()
	if !geoActive {
		t.Error("expected geoActive to be true for comma-separated pl,de rules")
	}

	// Verify caching behavior based on modTime
	// Set check time to empty, then run cached version
	geoActiveCheckTime = time.Time{}
	geoActiveCache = false

	cached1 := isGeoActiveCached()
	if !cached1 {
		t.Error("expected cached value to calculate to true")
	}

	// Modify file and verify it invalidates and recalculates (e.g. make it false by removing pl,de)
	if err := os.WriteFile(rf, []byte("allow in tcp 80 any\n"), 0644); err != nil {
		t.Fatal(err)
	}
	// Artificially advance mod time so os.Stat returns a newer time
	fut := time.Now().Add(10 * time.Second)
	os.Chtimes(rf, fut, fut)

	cached2 := isGeoActiveCached()
	if cached2 {
		t.Error("expected cache to invalidate and calculate to false after modifying rules file")
	}
}
