package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSecuritySetAbuseIPDBKey(t *testing.T) {
	tmpDir := t.TempDir()
	configFile = filepath.Join(tmpDir, "config")
	os.WriteFile(configFile, []byte("ABUSEIPDB_API_KEY=\"123\"\n"), 0644)

	err := setAbuseIPDBKey("\"; echo hacked; \"")
	if err == nil {
		t.Fatalf("expected error for invalid characters in setAbuseIPDBKey")
	}

	err = setAbuseIPDBKey("validkey123ABCD")
	if err != nil {
		t.Fatalf("expected success for valid key: %v", err)
	}
}

func TestSecuritySetConfigValue(t *testing.T) {
	tmpDir := t.TempDir()
	configFile = filepath.Join(tmpDir, "config")
	os.WriteFile(configFile, []byte("SOME_KEY=\"val\"\n"), 0644)

	err := setConfigValue("SOME_KEY", "\"; echo hacked; \"")
	if err == nil {
		t.Fatalf("expected error for invalid characters in setConfigValue")
	}

	err = setConfigValue("SOME_KEY", "eth0,eth1")
	if err != nil {
		t.Fatalf("expected success for valid val: %v", err)
	}
}
