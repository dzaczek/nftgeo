package main

import (
	"os"
	"path/filepath"
	"testing"
)

func BenchmarkRuleFiles(b *testing.B) {
	rulesDir = b.TempDir()
	rulesFile = filepath.Join(rulesDir, "rules.conf")

	for i := 0; i < 50; i++ {
		os.WriteFile(filepath.Join(rulesDir, "10-web.conf"), []byte("filter in tcp 80 any\nfilter in tcp 443 any\n"), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ruleFiles()
	}
}
