package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkPolicy(b *testing.B) {
	rulesDir = b.TempDir()
	rulesFile = filepath.Join(rulesDir, "rules.conf")

	os.WriteFile(rulesFile, []byte("filter in tcp 22 any\nzone dmz eth1 eth2\n"), 0644)
	for i := 0; i < 20; i++ {
		os.WriteFile(filepath.Join(rulesDir, fmt.Sprintf("%02d-web.conf", i)), []byte("filter in tcp 80 any\nfilter in tcp 443 any\n"), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = policy()
	}
}

func BenchmarkPolicyOptimized(b *testing.B) {
	rulesDir = b.TempDir()
	rulesFile = filepath.Join(rulesDir, "rules.conf")

	os.WriteFile(rulesFile, []byte("filter in tcp 22 any\nzone dmz eth1 eth2\n"), 0644)
	for i := 0; i < 20; i++ {
		os.WriteFile(filepath.Join(rulesDir, fmt.Sprintf("%02d-web.conf", i)), []byte("filter in tcp 80 any\nfilter in tcp 443 any\n"), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = policyOptimized()
	}
}
