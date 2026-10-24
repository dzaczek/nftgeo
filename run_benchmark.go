package main

import (
	"testing"
	"github.com/dzaczek/nftgeo/ui"
)

func BenchmarkPolicy(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = ui.policy()
	}
}
