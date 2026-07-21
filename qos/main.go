// nftgeo-qos applies the small, explicit egress QoS profile used by nftgeo.
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

const usage = `Usage: nftgeo-qos [--config FILE] [--state FILE] <validate|plan|apply|clear|status>

Manages egress traffic shaping with Linux tc/HTB. Configuration defaults to
/etc/nftgeo/qos.conf.  This beta shapes traffic leaving one interface; it does
not shape download/ingress traffic (that needs an IFB device).

Commands:
  validate  Parse and validate qos.conf without changing the host.
  plan      Print the tc commands that apply would run.
  apply     Replace the managed root qdisc and install classes/mark filters.
  clear     Remove a qdisc previously installed by nftgeo-qos.
  status    Print the active tc qdisc, classes, and mark filters.
`

type class struct {
	Name     string
	Mark     int
	Rate     string
	Ceil     string
	Priority int
	ID       int
}

type config struct {
	Enabled   bool
	Interface string
	Bandwidth string
	bps       int64
	Default   string
	Classes   []class
}

type state struct {
	Interface string `json:"interface"`
	Version   int    `json:"version"`
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
			if len(fields) != 2 || !regexp.MustCompile(`^[A-Za-z0-9_.:@-]+$`).MatchString(fields[1]) {
				return c, bad("invalid interface")
			}
			c.Interface = fields[1]
		case "bandwidth":
			if len(fields) != 2 {
				return c, bad("bandwidth needs one value")
			}
			c.Bandwidth = fields[1]
		case "default":
			if len(fields) != 2 {
				return c, bad("default needs a class name")
			}
			c.Default = fields[1]
		case "class":
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
			c.Classes = append(c.Classes, class{Name: fields[1], Mark: mark, Rate: fields[5], Ceil: fields[7], Priority: prio, ID: 10 + len(c.Classes)})
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
	if c.Interface == "" || c.Bandwidth == "" || c.Default == "" || len(c.Classes) == 0 {
		return c, fmt.Errorf("%s: enabled profile needs interface, bandwidth, default, and at least one class", path)
	}
	bps, err := parseBandwidth(c.Bandwidth)
	if err != nil {
		return c, err
	}
	c.bps = bps
	seenNames, seenMarks := map[string]bool{}, map[int]bool{}
	defaultFound := false
	for i := range c.Classes {
		cl := &c.Classes[i]
		if !regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*$`).MatchString(cl.Name) || seenNames[cl.Name] || seenMarks[cl.Mark] {
			return c, fmt.Errorf("%s: class names and marks must be unique", path)
		}
		seenNames[cl.Name], seenMarks[cl.Mark] = true, true
		if cl.Name == c.Default {
			defaultFound = true
		}
		rate, rbps, err := resolvedRate(cl.Rate, bps)
		if err != nil || rbps > bps {
			return c, fmt.Errorf("%s: class %s: invalid rate: %v", path, cl.Name, err)
		}
		ceil, cbps, err := resolvedRate(cl.Ceil, bps)
		if err != nil || cbps > bps || cbps < rbps {
			return c, fmt.Errorf("%s: class %s: ceil must be between rate and bandwidth", path, cl.Name)
		}
		cl.Rate, cl.Ceil = rate, ceil
	}
	if !defaultFound {
		return c, fmt.Errorf("%s: default class %q does not exist", path, c.Default)
	}
	return c, nil
}

func tcPlan(c config, tc string) [][]string {
	if !c.Enabled {
		return nil
	}
	defaultID := 0
	for _, cl := range c.Classes {
		if cl.Name == c.Default {
			defaultID = cl.ID
		}
	}
	cmds := [][]string{{tc, "qdisc", "replace", "dev", c.Interface, "root", "handle", "1:", "htb", "default", strconv.Itoa(defaultID)}}
	for _, cl := range c.Classes {
		cmds = append(cmds,
			[]string{tc, "class", "replace", "dev", c.Interface, "parent", "1:", "classid", fmt.Sprintf("1:%d", cl.ID), "htb", "rate", cl.Rate, "ceil", cl.Ceil, "prio", strconv.Itoa(cl.Priority)},
			[]string{tc, "qdisc", "replace", "dev", c.Interface, "parent", fmt.Sprintf("1:%d", cl.ID), "handle", fmt.Sprintf("%d0:", cl.ID), "fq_codel"},
			[]string{tc, "filter", "replace", "dev", c.Interface, "parent", "1:", "protocol", "all", "prio", strconv.Itoa(cl.ID), "handle", strconv.Itoa(cl.Mark), "fw", "flowid", fmt.Sprintf("1:%d", cl.ID)},
		)
	}
	return cmds
}

func run(cmd []string) error {
	c := exec.Command(cmd[0], cmd[1:]...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	return c.Run()
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
	if s.Interface == "" || s.Version != 1 {
		return state{}, errors.New("invalid qos state")
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
	if err := run([]string{tc, "qdisc", "del", "dev", s.Interface, "root"}); err != nil {
		return fmt.Errorf("clear %s: %w", s.Interface, err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	fmt.Printf("nftgeo-qos: removed managed qdisc from %s\n", s.Interface)
	return nil
}

func main() {
	configPath := flag.String("config", "/etc/nftgeo/qos.conf", "QoS configuration file")
	statePath := flag.String("state", "/run/nftgeo/qos.json", "managed state file")
	tc := flag.String("tc", "tc", "tc binary")
	flag.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	flag.Parse()
	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(2)
	}
	command := flag.Arg(0)
	c, err := parseConfig(*configPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
		os.Exit(1)
	}
	switch command {
	case "validate":
		if c.Enabled {
			fmt.Printf("nftgeo-qos: valid egress profile on %s (%s, %d classes)\n", c.Interface, c.Bandwidth, len(c.Classes))
		} else {
			fmt.Println("nftgeo-qos: disabled")
		}
	case "plan":
		if !c.Enabled {
			fmt.Println("nftgeo-qos: disabled; apply would clear a qdisc managed by nftgeo-qos")
			return
		}
		fmt.Printf("# Egress only: %s at %s\n", c.Interface, c.Bandwidth)
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
		if _, err := net.InterfaceByName(c.Interface); err != nil {
			fmt.Fprintf(os.Stderr, "nftgeo-qos: interface %s is unavailable: %v\n", c.Interface, err)
			os.Exit(1)
		}
		for _, cmd := range tcPlan(c, *tc) {
			if err := run(cmd); err != nil {
				fmt.Fprintln(os.Stderr, "nftgeo-qos: apply failed; removing partial managed qdisc")
				_ = run([]string{*tc, "qdisc", "del", "dev", c.Interface, "root"})
				os.Exit(1)
			}
		}
		if err := os.MkdirAll(filepath.Dir(*statePath), 0755); err != nil {
			fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
			os.Exit(1)
		}
		b, _ := json.Marshal(state{Interface: c.Interface, Version: 1})
		if err := os.WriteFile(*statePath, b, 0600); err != nil {
			fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
			os.Exit(1)
		}
		fmt.Printf("nftgeo-qos: applied egress shaping to %s (%s)\n", c.Interface, c.Bandwidth)
	case "clear":
		if os.Geteuid() != 0 {
			fmt.Fprintln(os.Stderr, "nftgeo-qos: clear requires root")
			os.Exit(1)
		}
		if err := clear(*statePath, *tc); err != nil {
			fmt.Fprintln(os.Stderr, "nftgeo-qos:", err)
			os.Exit(1)
		}
	case "status":
		if !c.Enabled {
			fmt.Println("nftgeo-qos: disabled")
			return
		}
		fmt.Printf("nftgeo-qos: configured egress shaping on %s (%s)\n", c.Interface, c.Bandwidth)
		for _, args := range [][]string{{"qdisc", "show", "dev", c.Interface}, {"class", "show", "dev", c.Interface}, {"filter", "show", "dev", c.Interface}} {
			if err := run(append([]string{*tc}, args...)); err != nil {
				os.Exit(1)
			}
		}
	default:
		flag.Usage()
		os.Exit(2)
	}
}
