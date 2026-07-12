package main

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkFeedLabels(b *testing.B) {
	// Create a dummy config file
	tmp := b.TempDir()
	origGroupsDir := groupsDir
	origObjLiveFile := objLiveFile
	defer func() {
		groupsDir = origGroupsDir
		objLiveFile = origObjLiveFile
	}()
	groupsDir = tmp
	objLiveFile = filepath.Join(groupsDir, "ui-objects.conf")

	// Create some dummy content
	content := `
FEED "GREENSNOW" {
	https://blocklist.greensnow.co/greensnow.txt
}
FEED "DROP" {
	https://www.spamhaus.org/drop/drop.txt
}
`
	err := os.WriteFile(objLiveFile, []byte(content), 0644)
	if err != nil {
		b.Fatalf("Failed to write test file: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		feedLabels()
	}
}
