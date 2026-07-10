//go:build !linux

// NFLOG needs Linux netlink; on other platforms (e.g. a macOS dev build) the
// listener is a no-op and the dashboard uses the kernel-log path.
package main

func startNflog()                   {}
func nflogActive() bool             { return false }
func nflogDropsSince(string) []Drop { return nil }
