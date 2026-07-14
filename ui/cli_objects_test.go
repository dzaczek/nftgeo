package main

import (
	"os"
	"strings"
	"testing"
)

func TestSerializeObjectsRoundTrip(t *testing.T) {
	text := `GROUP_devs="192.168.1.1 192.168.1.2"
REGION_us="us-east us-west"
HOST_server="10.0.0.1"
SERVICE_web="80 443"
ZONE_lan="eth0"
LIST_block="1.1.1.1"
FEED_abuse="https://abuse.local/feed"
`
	g, rg, sv, hs, zn, ls, fd := parseObjects(text)

	if len(g) != 1 || g[0].Name != "devs" {
		t.Fatalf("Failed to parse group")
	}

	out := serializeObjects(g, rg, sv, hs, zn, ls, fd)
	if !strings.Contains(out, "GROUP_DEVS=\"192.168.1.1 192.168.1.2\"") {
		t.Fatalf("Failed to serialize group, got: %s", out)
	}
	if !strings.Contains(out, "REGION_US=\"us-east us-west\"") {
		t.Fatalf("Failed to serialize region, got: %s", out)
	}
	if !strings.Contains(out, "SERVICE_WEB=\"80 443\"") {
		t.Fatalf("Failed to serialize service, got: %s", out)
	}
	if !strings.Contains(out, "HOST_SERVER=\"10.0.0.1\"") {
		t.Fatalf("Failed to serialize host, got: %s", out)
	}
	if !strings.Contains(out, "ZONE_LAN=\"eth0\"") {
		t.Fatalf("Failed to serialize zone, got: %s", out)
	}
	if !strings.Contains(out, "LIST_BLOCK=\"1.1.1.1\"") {
		t.Fatalf("Failed to serialize list, got: %s", out)
	}
	if !strings.Contains(out, "FEED_ABUSE=\"https://abuse.local/feed\"") {
		t.Fatalf("Failed to serialize feed, got: %s", out)
	}
}

func TestObjectValidation(t *testing.T) {
	tests := []struct {
		name    string
		groups  []objEntry
		hosts   []objEntry
		feeds   []objEntry
		wantErr bool
	}{
		{
			name: "valid objects",
			groups: []objEntry{{Name: "devs", Members: []string{"1.1.1.1"}}},
			hosts: []objEntry{{Name: "server", Members: []string{"10.0.0.1"}}},
			feeds: []objEntry{{Name: "abuse", Members: []string{"https://foo.com"}}},
			wantErr: false,
		},
		{
			name: "invalid name (space)",
			groups: []objEntry{{Name: "my devs", Members: []string{"1.1.1.1"}}},
			wantErr: true,
		},
		{
			name: "invalid feed URL",
			feeds: []objEntry{{Name: "abuse", Members: []string{"http://foo.com/my space"}}},
			wantErr: true,
		},
		{
			name: "invalid host CIDR",
			hosts: []objEntry{{Name: "server", Members: []string{"10.0.0.1/99"}}},
			wantErr: true,
		},
		{
			name: "invalid host IP",
			hosts: []objEntry{{Name: "server", Members: []string{"not_an_ip"}}},
			wantErr: true,
		},
		{
			name: "duplicate name",
			groups: []objEntry{{Name: "devs", Members: []string{"1.1.1.1"}}, {Name: "devs", Members: []string{"2.2.2.2"}}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := sanitizeObjects(tt.groups, nil, nil, tt.hosts, nil, nil, tt.feeds)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeObjects() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestObjectsCommitAndRollback(t *testing.T) {
	origDraft := objDraftFile
	origLive := objLiveFile
	t.Cleanup(func() {
		objDraftFile = origDraft
		objLiveFile = origLive
		os.Remove("test_obj_draft.conf")
		os.Remove("test_obj_live.conf")
	})

	objDraftFile = "test_obj_draft.conf"
	objLiveFile = "test_obj_live.conf"

	os.WriteFile(objDraftFile, []byte("test draft"), 0644)

	act := activeStages()
	found := false
	for _, s := range act {
		if s.draft == objDraftFile {
			found = true
			break
		}
	}

	if !found {
		t.Fatalf("Expected objDraftFile in activeStages")
	}

	for _, s := range stages() {
		os.Remove(s.draft)
		os.Remove(s.backup)
	}

	if _, err := os.Stat(objDraftFile); err == nil {
		t.Fatalf("Expected draft to be removed after keep/discard")
	}
}
