// nftgeo-qos applies the explicit QoS profiles used by nftgeo.
// It deliberately owns only qdiscs it records in /run/nftgeo/qos.json.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const usage = `Usage: nftgeo-qos [--config FILE] [--state FILE] [--json] <validate|plan|apply|clear|status|diagnose>

Manages egress and ingress traffic shaping with Linux tc/HTB/CAKE. Configuration
defaults to /etc/nftgeo/qos.conf.

Commands:
  validate  Parse and validate qos.conf without changing the host.
  plan      Print the tc commands that apply would run.
  apply     Replace the managed root qdisc and install classes/mark filters.
  clear     Remove a qdisc previously installed by nftgeo-qos.
  status    Print the active tc qdiscs, classes, and mark filters.
  diagnose  Run diagnostic checks on interfaces and link speeds.
`

type class struct {
	Name     string `json:"name"`
	Mark     int    `json:"mark"`
	Rate     string `json:"rate"`
	Ceil     string `json:"ceil"`
	Priority int    `json:"priority"`
	ID       int    `json:"id"`
}

type directionConfig struct {
	Direction string `json:"direction"` // "upload" (egress) or "download" (ingress)
	Bandwidth string `json:"bandwidth"`
	bps       int64
	Default   string  `json:"default"`
	Qdisc     string  `json:"qdisc"`    // "htb", "cake", "fq_codel"
	Overhead  string  `json:"overhead"` // e.g. "ethernet", "atm", etc.
	Classes   []class `json:"classes"`
}

type interfaceConfig struct {
	Name       string            `json:"name"`
	Takeover   bool              `json:"takeover"`
	Directions []directionConfig `json:"directions"`
}

type config struct {
	Enabled   bool    `json:"enabled"`
	Interface string  `json:"interface"` // Legacy single-interface fallback
	Bandwidth string  `json:"bandwidth"` // Legacy single-interface fallback
	bps       int64   // Legacy single-interface fallback
	Default   string  `json:"default"` // Legacy single-interface fallback
	Classes   []class `json:"classes"` // Legacy single-interface fallback

	Interfaces []interfaceConfig `json:"interfaces"`
}

type state struct {
	Interfaces []string `json:"interfaces"`
	Version    int      `json:"version"`
}

type ClassStats struct {
	ClassID    string `json:"class_id"`
	SentBytes  uint64 `json:"sent_bytes"`
	SentPkts   uint64 `json:"sent_pkts"`
	Dropped    uint64 `json:"dropped"`
	Overlimits uint64 `json:"overlimits"`
	Backlog    uint64 `json:"backlog"`
}

type QdiscStats struct {
	QdiscType  string `json:"qdisc_type"`
	SentBytes  uint64 `json:"sent_bytes"`
	SentPkts   uint64 `json:"sent_pkts"`
	Dropped    uint64 `json:"dropped"`
	Overlimits uint64 `json:"overlimits"`
	Backlog    uint64 `json:"backlog"`
}

type LiveDirectionTelemetry struct {
	Direction string                `json:"direction"`
	Qdisc     string                `json:"qdisc"`
	Bandwidth string                `json:"bandwidth"`
	Drift     bool                  `json:"drift"`
	Qdiscs    map[string]QdiscStats `json:"qdiscs"`
	Classes   map[string]ClassStats `json:"classes"`
}

type LiveInterfaceTelemetry struct {
	Name       string                   `json:"name"`
	Directions []LiveDirectionTelemetry `json:"directions"`
}

type LiveQoSTelemetry struct {
	Enabled    bool                     `json:"enabled"`
	Drift      bool                     `json:"drift"`
	Interfaces []LiveInterfaceTelemetry `json:"interfaces"`
	Warnings   []string                 `json:"warnings"`
}

var rateRE = regexp.MustCompile(`^([1-9][0-9]*)(bit|kbit|mbit|gbit)$`)

func parseBandwidth(v string) (int64, error) {
	m := rateRE.FindStringSubmatch(strings.ToLower(v))
	if m == nil {
		return 0, fmt.Errorf("invalid bandwidth %q (use e.g. 100mbit)", v)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, err
	}
	mul := int64(1)
	switch m[2] {
	case "kbit":
		mul = 1000
	case "mbit":
		mul = 1000 * 1000
	case "gbit":
		mul = 1000 * 1000 * 1000
	}
	if n > (1<<63-1)/mul {
		return 0, fmt.Errorf("bandwidth %q is too large", v)
	}
	return n * mul, nil
}

func resolvedRate(v string, bandwidth int64) (string, int64, error) {
	v = strings.ToLower(v)
	if strings.HasSuffix(v, "%") {
		n, err := strconv.ParseInt(strings.TrimSuffix(v, "%"), 10, 64)
		if err != nil || n < 1 || n > 100 {
			return "", 0, fmt.Errorf("invalid percentage %q", v)
		}
		bps := bandwidth * n / 100
		return fmt.Sprintf("%dbit", bps), bps, nil
	}
	bps, err := parseBandwidth(v)
	if err != nil {
		return "", 0, err
	}
	return fmt.Sprintf("%dbit", bps), bps, nil
}

func parseConfig(path string) (config, error) {
	f, err := os.Open(path)
	if err != nil {
		return config{}, err
	}
	defer f.Close()
	c := config{}
	lineNo := 0
	s := bufio.NewScanner(f)

	currentIfaceIdx := -1
	currentDirIdx := -1

	ensureDirContext := func() error {
		if currentIfaceIdx == -1 {
			return errors.New("must specify an interface first")
		}
		if currentDirIdx == -1 {
			// Auto-create default upload context (backward compatibility for legacy single interface configuration)
			dirIdx := -1
			for j, d := range c.Interfaces[currentIfaceIdx].Directions {
				if d.Direction == "upload" {
					dirIdx = j
					break
				}
			}
			if dirIdx == -1 {
				c.Interfaces[currentIfaceIdx].Directions = append(c.Interfaces[currentIfaceIdx].Directions, directionConfig{
					Direction: "upload",
					Qdisc:     "htb",
				})
				dirIdx = len(c.Interfaces[currentIfaceIdx].Directions) - 1
			}
			currentDirIdx = dirIdx
		}
		return nil
	}

	for s.Scan() {
		lineNo++
		line := strings.TrimSpace(strings.SplitN(s.Text(), "#", 2)[0])
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		bad := func(format string, a ...interface{}) error {
			return fmt.Errorf("%s:%d: %s", path, lineNo, fmt.Sprintf(format, a...))
		}

		switch fields[0] {
		case "enabled":
			if len(fields) != 2 || (fields[1] != "yes" && fields[1] != "no") {
				return c, bad("enabled must be yes or no")
			}
			c.Enabled = fields[1] == "yes"

		case "interface":
			if len(fields) < 2 || len(fields) > 3 {
				return c, bad("interface syntax: interface NAME [takeover]")
			}
			name := fields[1]
			if !regexp.MustCompile(`^[A-Za-z0-9_.:@-]+$`).MatchString(name) {
				return c, bad("invalid interface name %q", name)
			}
			takeover := false
			if len(fields) == 3 {
				if fields[2] != "takeover" {
					return c, bad("expected 'takeover', got %q", fields[2])
				}
				takeover = true
			}

			// Find or create interface
			idx := -1
			for i, iface := range c.Interfaces {
				if iface.Name == name {
					idx = i
					break
				}
			}
			if idx == -1 {
				c.Interfaces = append(c.Interfaces, interfaceConfig{
					Name:     name,
					Takeover: takeover,
				})
				idx = len(c.Interfaces) - 1
			} else {
				if takeover {
					c.Interfaces[idx].Takeover = true
				}
			}
			currentIfaceIdx = idx
			currentDirIdx = -1 // Reset direction context

		case "direction":
			if currentIfaceIdx == -1 {
				return c, bad("direction must be specified under an interface")
			}
			if len(fields) != 2 || (fields[1] != "upload" && fields[1] != "download") {
				return c, bad("direction must be upload or download")
			}
			dir := fields[1]
			dirIdx := -1
			for j, d := range c.Interfaces[currentIfaceIdx].Directions {
				if d.Direction == dir {
					dirIdx = j
					break
				}
			}
			if dirIdx == -1 {
				c.Interfaces[currentIfaceIdx].Directions = append(c.Interfaces[currentIfaceIdx].Directions, directionConfig{
					Direction: dir,
					Qdisc:     "htb",
				})
				dirIdx = len(c.Interfaces[currentIfaceIdx].Directions) - 1
			}
			currentDirIdx = dirIdx

		case "bandwidth":
			if err := ensureDirContext(); err != nil {
				return c, bad("%s", err.Error())
			}
			if len(fields) != 2 {
				return c, bad("bandwidth needs one value")
			}
			c.Interfaces[currentIfaceIdx].Directions[currentDirIdx].Bandwidth = fields[1]

		case "default":
			if err := ensureDirContext(); err != nil {
				return c, bad("%s", err.Error())
			}
			if len(fields) != 2 {
				return c, bad("default needs a class name")
			}
			c.Interfaces[currentIfaceIdx].Directions[currentDirIdx].Default = fields[1]

		case "qdisc":
			if err := ensureDirContext(); err != nil {
				return c, bad("%s", err.Error())
			}
			if len(fields) != 2 || (fields[1] != "htb" && fields[1] != "cake" && fields[1] != "fq_codel") {
				return c, bad("qdisc must be htb, cake, or fq_codel")
			}
			c.Interfaces[currentIfaceIdx].Directions[currentDirIdx].Qdisc = fields[1]

		case "overhead":
			if err := ensureDirContext(); err != nil {
				return c, bad("%s", err.Error())
			}
			if len(fields) != 2 {
				return c, bad("overhead needs one value")
			}
			c.Interfaces[currentIfaceIdx].Directions[currentDirIdx].Overhead = fields[1]

		case "class":
			if err := ensureDirContext(); err != nil {
				return c, bad("%s", err.Error())
			}
			if (len(fields) != 8 && len(fields) != 10) || fields[2] != "mark" || fields[4] != "rate" || fields[6] != "ceil" || (len(fields) == 10 && fields[8] != "priority") {
				return c, bad("class syntax: class NAME mark NUMBER rate RATE ceil RATE [priority 0-7]")
			}
			mark, e1 := strconv.Atoi(fields[3])
			prio := 3
			var e2 error
			if len(fields) == 10 {
				prio, e2 = strconv.Atoi(fields[9])
			}
			if e1 != nil || mark < 1 || mark > 65535 || e2 != nil || prio < 0 || prio > 7 {
				return c, bad("class mark must be 1..65535 and priority 0..7")
			}

			dirConf := &c.Interfaces[currentIfaceIdx].Directions[currentDirIdx]
			dirConf.Classes = append(dirConf.Classes, class{
				Name:     fields[1],
				Mark:     mark,
				Rate:     fields[5],
				Ceil:     fields[7],
				Priority: prio,
				ID:       10 + len(dirConf.Classes),
			})

		default:
			return c, bad("unknown directive %q", fields[0])
		}
	}

	if err := s.Err(); err != nil {
		return c, err
	}

	if !c.Enabled {
		return c, nil
	}

	// Validate parsed configuration
	if len(c.Interfaces) == 0 {
		return c, fmt.Errorf("%s: enabled profile needs at least one interface defined", path)
	}

	for i := range c.Interfaces {
		iface := &c.Interfaces[i]
		if len(iface.Directions) == 0 {
			return c, fmt.Errorf("%s: interface %s needs at least one direction config", path, iface.Name)
		}
		for j := range iface.Directions {
			dirConf := &iface.Directions[j]
			if dirConf.Bandwidth == "" {
				return c, fmt.Errorf("%s: interface %s %s needs bandwidth", path, iface.Name, dirConf.Direction)
			}
			bps, err := parseBandwidth(dirConf.Bandwidth)
			if err != nil {
				return c, fmt.Errorf("%s: interface %s %s: %v", path, iface.Name, dirConf.Direction, err)
			}
			dirConf.bps = bps

			// For HTB we require default and classes
			if dirConf.Qdisc != "cake" {
				if dirConf.Default == "" || len(dirConf.Classes) == 0 {
					return c, fmt.Errorf("%s: interface %s %s needs default class and at least one class", path, iface.Name, dirConf.Direction)
				}
				seenNames, seenMarks := map[string]bool{}, map[int]bool{}
				defaultFound := false
				var totalRateBps int64

				for k := range dirConf.Classes {
					cl := &dirConf.Classes[k]
					if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`).MatchString(cl.Name) || seenNames[cl.Name] || seenMarks[cl.Mark] {
						return c, fmt.Errorf("%s: class names and marks must be unique on interface %s %s", path, iface.Name, dirConf.Direction)
					}
					seenNames[cl.Name], seenMarks[cl.Mark] = true, true
					if cl.Name == dirConf.Default {
						defaultFound = true
					}
					rate, rbps, err := resolvedRate(cl.Rate, bps)
					if err != nil || rbps > bps {
						return c, fmt.Errorf("%s: class %s on %s %s: invalid rate: %v", path, cl.Name, iface.Name, dirConf.Direction, err)
					}
					ceil, cbps, err := resolvedRate(cl.Ceil, bps)
					if err != nil || cbps > bps || cbps < rbps {
						return c, fmt.Errorf("%s: class %s on %s %s: ceil must be between rate and bandwidth", path, cl.Name, iface.Name, dirConf.Direction)
					}
					cl.Rate, cl.Ceil = rate, ceil
					totalRateBps += rbps
				}

				if !defaultFound {
					return c, fmt.Errorf("%s: default class %q does not exist on %s %s", path, dirConf.Default, iface.Name, dirConf.Direction)
				}

				// Guarantee check
				if totalRateBps > bps {
					return c, fmt.Errorf("%s: interface %s %s: aggregate guaranteed class rates (%v bps) exceed total bandwidth %s (%v bps)",
						path, iface.Name, dirConf.Direction, totalRateBps, dirConf.Bandwidth, bps)
				}
			}
		}
	}

	// Populate legacy single-interface fallback fields
	if len(c.Interfaces) > 0 {
		c.Interface = c.Interfaces[0].Name
		if len(c.Interfaces[0].Directions) > 0 {
			dirConf := c.Interfaces[0].Directions[0]
			c.Bandwidth = dirConf.Bandwidth
			c.bps = dirConf.bps
			c.Default = dirConf.Default
			c.Classes = dirConf.Classes
		}
	}

	return c, nil
}

func tcPlan(c config, tc string) [][]string {
	if !c.Enabled {
		return nil
	}
	var cmds [][]string

	// Make a plan for each interface and direction
	for _, iface := range c.Interfaces {
		for _, dirConf := range iface.Directions {
			dev := iface.Name
			if dirConf.Direction == "download" {
				dev = "ifb-" + iface.Name
				// Generate Ingress/Download environment setup command lines
				cmds = append(cmds,
					[]string{"modprobe", "ifb"},
					[]string{"ip", "link", "add", "name", dev, "type", "ifb"},
					[]string{"ip", "link", "set", "dev", dev, "up"},
					[]string{tc, "qdisc", "replace", "dev", iface.Name, "handle", "ffff:", "ingress"},
					[]string{tc, "filter", "replace", "dev", iface.Name, "parent", "ffff:", "protocol", "all", "prio", "1", "u32", "match", "u32", "0", "0", "action", "mirred", "egress", "redirect", "dev", dev},
				)
			}

			if dirConf.Qdisc == "cake" {
				overheadArgs := []string{}
				if dirConf.Overhead != "" {
					overheadArgs = append(overheadArgs, "overhead", dirConf.Overhead)
				}
				cmds = append(cmds, append([]string{tc, "qdisc", "replace", "dev", dev, "root", "cake", "bandwidth", dirConf.Bandwidth}, overheadArgs...))
			} else {
				// htb (default)
				defaultID := 0
				for _, cl := range dirConf.Classes {
					if cl.Name == dirConf.Default {
						defaultID = cl.ID
					}
				}

				cmds = append(cmds, []string{tc, "qdisc", "replace", "dev", dev, "root", "handle", "1:", "htb", "default", strconv.Itoa(defaultID)})

				// Create root parent class representing physical link budget
				overheadArgs := []string{}
				if dirConf.Overhead != "" {
					overheadArgs = append(overheadArgs, "overhead", dirConf.Overhead)
				}
				cmds = append(cmds, append([]string{tc, "class", "replace", "dev", dev, "parent", "1:", "classid", "1:1", "htb", "rate", dirConf.Bandwidth}, overheadArgs...))

				for _, cl := range dirConf.Classes {
					cmds = append(cmds,
						[]string{tc, "class", "replace", "dev", dev, "parent", "1:1", "classid", fmt.Sprintf("1:%d", cl.ID), "htb", "rate", cl.Rate, "ceil", cl.Ceil, "prio", strconv.Itoa(cl.Priority)},
						[]string{tc, "qdisc", "replace", "dev", dev, "parent", fmt.Sprintf("1:%d", cl.ID), "handle", fmt.Sprintf("%d0:", cl.ID), "fq_codel"},
						[]string{tc, "filter", "replace", "dev", dev, "parent", "1:", "protocol", "all", "prio", strconv.Itoa(cl.ID), "handle", strconv.Itoa(cl.Mark), "fw", "flowid", fmt.Sprintf("1:%d", cl.ID)},
					)
				}
			}
		}
	}

	return cmds
}

func cleanVal(s string) string {
	return strings.TrimFunc(s, func(r rune) bool {
		return r < '0' || r > '9'
	})
}

func run(cmd []string) error {
	c := exec.Command(cmd[0], cmd[1:]...)
	var stderr strings.Builder
	c.Stdout = os.Stdout
	c.Stderr = &stderr
	err := c.Run()
	if err != nil {
		errStr := stderr.String()
		if (cmd[0] == "ip" && strings.Contains(errStr, "File exists")) ||
			(cmd[0] == "modprobe" && (strings.Contains(errStr, "not found") || strings.Contains(errStr, "Permission denied") || strings.Contains(errStr, "not permitted"))) {
			return nil
		}
		os.Stderr.WriteString(errStr)
		return err
	}
	return nil
}

func parseClassStats(output string) map[string]ClassStats {
	stats := map[string]ClassStats{}
	lines := strings.Split(output, "\n")
	var currentID string
	var currentStats ClassStats

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "class ") {
			if currentID != "" {
				stats[currentID] = currentStats
			}
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				currentID = fields[2]
				currentStats = ClassStats{ClassID: currentID}
			} else {
				currentID = ""
			}
		} else if strings.HasPrefix(line, "Sent ") && currentID != "" {
			fields := strings.Fields(line)
			for idx, f := range fields {
				if f == "bytes" && idx > 0 {
					val, _ := strconv.ParseUint(cleanVal(fields[idx-1]), 10, 64)
					currentStats.SentBytes = val
				}
				if (f == "pkt" || f == "pkts") && idx > 0 {
					val, _ := strconv.ParseUint(cleanVal(fields[idx-1]), 10, 64)
					currentStats.SentPkts = val
				}
				if strings.Contains(f, "dropped") && idx+1 < len(fields) {
					val, _ := strconv.ParseUint(cleanVal(fields[idx+1]), 10, 64)
					currentStats.Dropped = val
				}
				if strings.Contains(f, "overlimits") && idx+1 < len(fields) {
					val, _ := strconv.ParseUint(cleanVal(fields[idx+1]), 10, 64)
					currentStats.Overlimits = val
				}
			}
		} else if strings.HasPrefix(line, "backlog ") && currentID != "" {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(cleanVal(fields[1]), 10, 64)
				currentStats.Backlog = val
			}
		}
	}
	if currentID != "" {
		stats[currentID] = currentStats
	}
	return stats
}

func parseQdiscStats(output string) map[string]QdiscStats {
	stats := map[string]QdiscStats{}
	lines := strings.Split(output, "\n")
	var currentID string
	var currentStats QdiscStats

	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "qdisc ") {
			if currentID != "" {
				stats[currentID] = currentStats
			}
			fields := strings.Fields(line)
			var h string
			for idx, f := range fields {
				if f == "handle" && idx+1 < len(fields) {
					h = fields[idx+1]
				}
			}
			if h == "" && len(fields) >= 3 {
				h = fields[2]
			}
			currentID = h
			qdiscType := ""
			if len(fields) >= 2 {
				qdiscType = fields[1]
			}
			currentStats = QdiscStats{QdiscType: qdiscType}
		} else if strings.HasPrefix(line, "Sent ") && currentID != "" {
			fields := strings.Fields(line)
			for idx, f := range fields {
				if f == "bytes" && idx > 0 {
					val, _ := strconv.ParseUint(cleanVal(fields[idx-1]), 10, 64)
					currentStats.SentBytes = val
				}
				if (f == "pkt" || f == "pkts") && idx > 0 {
					val, _ := strconv.ParseUint(cleanVal(fields[idx-1]), 10, 64)
					currentStats.SentPkts = val
				}
				if strings.Contains(f, "dropped") && idx+1 < len(fields) {
					val, _ := strconv.ParseUint(cleanVal(fields[idx+1]), 10, 64)
					currentStats.Dropped = val
				}
				if strings.Contains(f, "overlimits") && idx+1 < len(fields) {
					val, _ := strconv.ParseUint(cleanVal(fields[idx+1]), 10, 64)
					currentStats.Overlimits = val
				}
			}
		} else if strings.HasPrefix(line, "backlog ") && currentID != "" {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				val, _ := strconv.ParseUint(cleanVal(fields[1]), 10, 64)
				currentStats.Backlog = val
			}
		}
	}
	if currentID != "" {
		stats[currentID] = currentStats
	}
	return stats
}

func detectDriftForDirection(dirConf directionConfig, liveClasses map[string]ClassStats, liveQdiscs map[string]QdiscStats) bool {
	if dirConf.Qdisc != "cake" {
		for _, cl := range dirConf.Classes {
			classID := fmt.Sprintf("1:%d", cl.ID)
			if _, exists := liveClasses[classID]; !exists {
				return true
			}
		}
	}
	hasRootQdisc := false
	for _, qd := range liveQdiscs {
		if qd.QdiscType == dirConf.Qdisc {
			hasRootQdisc = true
		}
	}
	if !hasRootQdisc && len(liveQdiscs) > 0 {
		return true
	}
	return false
}

func readState(path string) (state, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return state{}, err
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return state{}, err
	}
	if s.Version != 1 {
		return state{}, errors.New("invalid qos state version")
	}
	return s, nil
}

func clear(path, tc string) error {
	s, err := readState(path)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("nftgeo-qos: no managed qdisc")
			return nil
		}
		return err
	}

	for _, ifaceName := range s.Interfaces {
		// Clean up ingress IFB redirect first
		_ = run([]string{tc, "qdisc", "del", "dev", ifaceName, "ingress"})
		dev := "ifb-" + ifaceName
		_ = run([]string{"ip", "link", "set", "dev", dev, "down"})
		_ = run([]string{"ip", "link", "delete", "dev", dev, "type", "ifb"})

		// Clean up egress root qdisc
		if err := run([]string{tc, "qdisc", "del", "dev", ifaceName, "root"}); err != nil {
			fmt.Fprintf(os.Stderr, "clear %s: %v\n", ifaceName, err)
		}
	}

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Printf("nftgeo-qos: removed managed qdisc from %v\n", s.Interfaces)
	return nil
}

func main() {
	configPath := flag.String("config", "/etc/nftgeo/qos.conf", "QoS configuration file")
	statePath := flag.String("state", "/run/nftgeo/qos.json", "managed state file")
	tc := flag.String("tc", "tc", "tc binary")
	jsonOut := flag.Bool("json", false, "output in JSON format")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	command := flag.Arg(0)
	c, err := parseConfig(*configPath)
	if err != nil {
		if *jsonOut {
			b, _ := json.Marshal(map[string]interface{}{"valid": false, "error": err.Error()})
			fmt.Println(string(b))
		} else {
			fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
		}
		os.Exit(1)
	}
	switch command {
	case "validate":
		if *jsonOut {
			b, _ := json.Marshal(map[string]interface{}{"valid": true, "interfaces_count": len(c.Interfaces)})
			fmt.Println(string(b))
		} else {
			if c.Enabled {
				fmt.Printf("nftgeo-qos: valid profile with %d interfaces\n", len(c.Interfaces))
			} else {
				fmt.Println("nftgeo-qos: disabled")
			}
		}
	case "plan":
		if *jsonOut {
			cmds := tcPlan(c, *tc)
			b, _ := json.Marshal(map[string]interface{}{"commands": cmds})
			fmt.Println(string(b))
			return
		}
		if !c.Enabled {
			fmt.Println("nftgeo-qos: disabled; apply would clear a qdisc managed by nftgeo-qos")
			return
		}
		for _, iface := range c.Interfaces {
			fmt.Printf("# Interface: %s\n", iface.Name)
		}
		for _, cmd := range tcPlan(c, *tc) {
			fmt.Println(strings.Join(cmd, " "))
		}
	case "apply":
		if !c.Enabled {
			if err := clear(*statePath, *tc); err != nil {
				fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
				os.Exit(1)
			}
			return
		}
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "nftgeo-qos: apply requires root")
			os.Exit(1)
		}

		// Check if any of the interfaces has a non-nftgeo qdisc already, and require takeover
		managedState, _ := readState(*statePath)
		managedMap := map[string]bool{}
		for _, mIface := range managedState.Interfaces {
			managedMap[mIface] = true
		}

		for _, iface := range c.Interfaces {
			if _, err := net.InterfaceByName(iface.Name); err != nil {
				fmt.Fprintf(os.Stderr, "nftgeo-qos: interface %s is unavailable: %v\n", iface.Name, err)
				os.Exit(1)
			}

			// Detect pre-existing root qdisc that is not managed by us and is not default/pfifo_fast/noqueue
			if !managedMap[iface.Name] && !iface.Takeover {
				out, err := exec.Command(*tc, "qdisc", "show", "dev", iface.Name).Output()
				if err == nil && len(out) > 0 {
					qdiscStr := string(out)
					if !strings.Contains(qdiscStr, "pfifo_fast") && !strings.Contains(qdiscStr, "noqueue") && !strings.Contains(qdiscStr, "mq") && strings.Contains(qdiscStr, "root") {
						fmt.Fprintf(os.Stderr, "nftgeo-qos: pre-existing non-nftgeo root qdisc detected on %s. Require takeover confirmation in config or command line.\n", iface.Name)
						os.Exit(1)
					}
				}
			}
		}

		// Apply the plan
		for _, cmd := range tcPlan(c, *tc) {
			if err := run(cmd); err != nil {
				fmt.Fprintln(os.Stderr, "nftgeo-qos: apply failed; removing partial managed qdiscs")
				for _, iface := range c.Interfaces {
					_ = run([]string{*tc, "qdisc", "del", "dev", iface.Name, "root"})
					_ = run([]string{*tc, "qdisc", "del", "dev", iface.Name, "ingress"})
					dev := "ifb-" + iface.Name
					_ = run([]string{"ip", "link", "set", "dev", dev, "down"})
					_ = run([]string{"ip", "link", "delete", "dev", dev, "type", "ifb"})
				}
				os.Exit(1)
			}
		}

		if err := os.MkdirAll(filepath.Dir(*statePath), 0755); err != nil {
			fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
			os.Exit(1)
		}

		var ifaceNames []string
		for _, iface := range c.Interfaces {
			ifaceNames = append(ifaceNames, iface.Name)
		}
		b, _ := json.Marshal(state{Interfaces: ifaceNames, Version: 1})
		if err := os.WriteFile(*statePath, b, 0600); err != nil {
			fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
			os.Exit(1)
		}
		if *jsonOut {
			res, _ := json.Marshal(map[string]interface{}{"success": true, "interfaces": ifaceNames})
			fmt.Println(string(res))
		} else {
			fmt.Printf("nftgeo-qos: applied QoS shaping to %v\n", ifaceNames)
		}

	case "clear":
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "nftgeo-qos: clear requires root")
			os.Exit(1)
		}
		if err := clear(*statePath, *tc); err != nil {
			fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
			os.Exit(1)
		}
		if *jsonOut {
			res, _ := json.Marshal(map[string]interface{}{"success": true})
			fmt.Println(string(res))
		}
	case "status":
		telemetry := LiveQoSTelemetry{Enabled: c.Enabled, Drift: false}

		for _, iface := range c.Interfaces {
			ifaceTelem := LiveInterfaceTelemetry{Name: iface.Name}

			for _, dirConf := range iface.Directions {
				dev := iface.Name
				if dirConf.Direction == "download" {
					dev = "ifb-" + iface.Name
				}

				// Execute tc -s class show and tc -s qdisc show to gather live stats
				classOut, _ := exec.Command(*tc, "-s", "class", "show", "dev", dev).Output()
				qdiscOut, _ := exec.Command(*tc, "-s", "qdisc", "show", "dev", dev).Output()

				liveClasses := parseClassStats(string(classOut))
				liveQdiscs := parseQdiscStats(string(qdiscOut))

				drift := detectDriftForDirection(dirConf, liveClasses, liveQdiscs)
				if drift {
					telemetry.Drift = true
				}

				ifaceTelem.Directions = append(ifaceTelem.Directions, LiveDirectionTelemetry{
					Direction: dirConf.Direction,
					Qdisc:     dirConf.Qdisc,
					Bandwidth: dirConf.Bandwidth,
					Drift:     drift,
					Qdiscs:    liveQdiscs,
					Classes:   liveClasses,
				})
			}
			telemetry.Interfaces = append(telemetry.Interfaces, ifaceTelem)
		}

		if *jsonOut {
			b, _ := json.Marshal(telemetry)
			fmt.Println(string(b))
			return
		}

		if !c.Enabled {
			fmt.Println("nftgeo-qos: disabled")
			return
		}
		for _, iface := range telemetry.Interfaces {
			fmt.Printf("nftgeo-qos: configured shaping on %s (drift=%v)\n", iface.Name, telemetry.Drift)
			for _, dirTelem := range iface.Directions {
				fmt.Printf("  Direction: %s, Qdisc: %s, Bandwidth: %s, Drift: %v\n", dirTelem.Direction, dirTelem.Qdisc, dirTelem.Bandwidth, dirTelem.Drift)
				fmt.Printf("    Live Qdiscs counts: %d, Live Classes counts: %d\n", len(dirTelem.Qdiscs), len(dirTelem.Classes))
			}
		}
	case "diagnose":
		fmt.Println("=== nftgeo-qos diagnose ===")
		for _, iface := range c.Interfaces {
			netIface, err := net.InterfaceByName(iface.Name)
			if err != nil {
				fmt.Printf("Interface %s: NOT FOUND\n", iface.Name)
				continue
			}
			fmt.Printf("Interface %s: FOUND, MTU: %d, Flags: %v\n", iface.Name, netIface.MTU, netIface.Flags)
			speedPath := filepath.Join("/sys/class/net", iface.Name, "speed")
			if speedBytes, err := os.ReadFile(speedPath); err == nil {
				fmt.Printf("  Link speed: %s Mbps\n", strings.TrimSpace(string(speedBytes)))
			} else {
				fmt.Printf("  Link speed: autodetection unavailable\n")
			}
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}
