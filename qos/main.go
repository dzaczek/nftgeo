package main

import (
	"fmt"
	"os"
)

// This is the starting skeleton for the nftgeo-qos CLI tool.
// It will be responsible for parsing qos.conf and translating it into `tc` commands
// to establish Traffic Control queue disciplines and classes.

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: nftgeo-qos <apply|clear>")
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "apply":
		fmt.Println("nftgeo-qos: apply called")
		// 1. Read qos.conf (e.g., from /etc/nftgeo/qos.conf)
		// 2. Parse tree hierarchy and classes
		// 3. Setup IFB devices if necessary
		// 4. Execute `tc` commands to establish Root Qdisc (e.g., HTB) and classes
		fmt.Println("nftgeo-qos: apply complete (stub)")
	case "clear":
		fmt.Println("nftgeo-qos: clear called")
		// 1. Remove all configured tc qdiscs on managed interfaces
		fmt.Println("nftgeo-qos: clear complete (stub)")
	default:
		fmt.Printf("nftgeo-qos: unknown command '%s'\n", command)
		fmt.Println("Usage: nftgeo-qos <apply|clear>")
		os.Exit(1)
	}
}
