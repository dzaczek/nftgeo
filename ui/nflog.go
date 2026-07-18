//go:build linux

// NFLOG drop listener. The engine emits `log prefix "nftgeo-..." group N`, which
// delivers each logged packet to the nfnetlink_log multicast group N. Unlike the
// kernel ring buffer (host-only, invisible inside LXC/OpenVZ), NFLOG is network-
// namespace aware, so this listener receives drops even in a container — which is
// what makes the drop map/stats work there. On a host it works just as well, so
// the dashboard uses it uniformly and only falls back to journalctl when NFLOG
// can't be opened (group disabled, or no permission).
package main

import (
	"context"
	"encoding/binary"
	"log"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	nflog "github.com/florianl/go-nflog/v2"
)

// One hour of drops at the engine's 10/s-per-rule log cap is well under this;
// the ring is only the live 24h view, the persistent store is ui-stats.json.
const nflogRingMax = 50000

var (
	nflogMu   sync.RWMutex
	nflogRing []Drop
	nflogUp   bool
	nflogConn *nflog.Nflog // kept alive for the process lifetime
)

var reNflogPrefix = regexp.MustCompile(`^nftgeo-(drop|accept):(.+?)\s*$`)

const (
	defaultNFLOGGroup = 5
	maxNFLOGGroup     = 65535
)

// nflogGroup returns the NFLOG group the engine logs to: config NFLOG_GROUP,
// else env, else the default 5. 0 disables NFLOG (kernel-log mode).
func nflogGroup() int {
	v := strings.TrimSpace(os.Getenv("NFLOG_GROUP"))
	if data, err := os.ReadFile(configFile); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			t := strings.TrimSpace(line)
			if strings.HasPrefix(t, "NFLOG_GROUP=") {
				v = strings.Trim(strings.TrimSpace(t[len("NFLOG_GROUP="):]), `"`)
			}
		}
	}
	return parseNFLOGGroup(v)
}

func parseNFLOGGroup(v string) int {
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > maxNFLOGGroup {
		return defaultNFLOGGroup
	}
	return n
}

// startNflog opens the NFLOG group and registers the drop handler. Register is
// non-blocking (it reads in its own goroutine), so we keep the socket alive for
// the process lifetime. If NFLOG can't be opened (disabled, or lacking
// CAP_NET_ADMIN) the dashboard silently falls back to the kernel log.
func startNflog() {
	g := nflogGroup()
	if g <= 0 {
		return
	}
	nf, err := nflog.Open(&nflog.Config{
		Group:    uint16(g),
		Copymode: nflog.CopyPacket,
	})
	if err != nil {
		log.Printf("nflog: cannot open group %d (%v); drop stats fall back to the kernel log", g, err)
		return
	}
	hook := func(a nflog.Attribute) int {
		if a.Prefix == nil || a.Payload == nil || !strings.HasPrefix(*a.Prefix, "nftgeo-") {
			return 0
		}
		recordNflogDrop(parseNflog(*a.Prefix, *a.Payload, a.InDev, a.OutDev, a.Timestamp))
		return 0
	}
	errFn := func(e error) int { return 0 } // keep receiving past transient errors
	if err := nf.RegisterWithErrorFunc(context.Background(), hook, errFn); err != nil {
		log.Printf("nflog: register on group %d failed: %v; falling back to the kernel log", g, err)
		nf.Close()
		return
	}
	nflogMu.Lock()
	nflogUp = true
	nflogConn = nf
	nflogMu.Unlock()
	log.Printf("nflog: listening on group %d for drop stats", g)
}

func nflogActive() bool {
	nflogMu.RLock()
	defer nflogMu.RUnlock()
	return nflogUp
}

// nflogDropsSince returns ring records no older than the `since` window (e.g.
// "-24h"), newest-inclusive.
func nflogDropsSince(since string) []Drop {
	cutoff := time.Time{}
	if d, err := time.ParseDuration(since); err == nil {
		cutoff = time.Now().Add(d) // since is negative, e.g. -24h
	}
	nflogMu.RLock()
	defer nflogMu.RUnlock()
	out := make([]Drop, 0, len(nflogRing))
	for _, d := range nflogRing {
		if !cutoff.IsZero() {
			if t, err := time.Parse(time.RFC3339, d.Time); err == nil && t.Before(cutoff) {
				continue
			}
		}
		out = append(out, d)
	}
	return out
}

// recordNflogDrop appends to the live ring and, for drops, to the persistent
// top-IP/histogram store. Because the listener records directly, the journalctl
// ingest is disabled when NFLOG is active (see main), so there's no double count.
func recordNflogDrop(d Drop) {
	nflogMu.Lock()
	nflogRing = append(nflogRing, d)
	if len(nflogRing) > nflogRingMax {
		nflogRing = append([]Drop(nil), nflogRing[len(nflogRing)-nflogRingMax:]...)
	}
	nflogMu.Unlock()
	if d.Verdict != "drop" {
		return
	}
	ts := time.Now().Unix()
	if t, err := time.Parse(time.RFC3339, d.Time); err == nil {
		ts = t.Unix()
	}
	recordStats([]statsEntry{{Ts: ts, Src: d.Src, Dst: d.Dst, CC: d.CC, Port: d.Dport, Proto: d.Proto, Dir: d.Dir, Reason: d.Reason}})
}

// parseNflog turns one NFLOG packet (prefix + raw IP payload + in/out ifindex)
// into a Drop: verdict/reason from the prefix, addresses/proto/port from the IP
// header, direction from which interface index is set, country from geo lookup.
func parseNflog(prefix string, payload []byte, inDev, outDev *uint32, ts *time.Time) Drop {
	d := Drop{Verdict: "drop"}
	if m := reNflogPrefix.FindStringSubmatch(prefix); m != nil {
		d.Verdict = m[1]
		d.Reason = strings.TrimSpace(m[2])
	}
	t := time.Now()
	if ts != nil {
		t = *ts
	}
	d.Time = t.UTC().Format(time.RFC3339)

	if len(payload) >= 20 && payload[0]>>4 == 4 {
		ihl := int(payload[0]&0x0f) * 4
		proto := payload[9]
		d.Proto = protoName(proto)
		d.Src = net.IP(payload[12:16]).String()
		d.Dst = net.IP(payload[16:20]).String()
		if (proto == 6 || proto == 17) && len(payload) >= ihl+4 {
			d.Dport = strconv.Itoa(int(binary.BigEndian.Uint16(payload[ihl+2 : ihl+4])))
		}
	} else if len(payload) >= 40 && payload[0]>>4 == 6 {
		nh := payload[6]
		d.Proto = protoName(nh)
		d.Src = net.IP(payload[8:24]).String()
		d.Dst = net.IP(payload[24:40]).String()
		if (nh == 6 || nh == 17) && len(payload) >= 44 {
			d.Dport = strconv.Itoa(int(binary.BigEndian.Uint16(payload[42:44])))
		}
	}

	in := inDev != nil && *inDev != 0
	out := outDev != nil && *outDev != 0
	switch {
	case in && !out:
		d.Dir = "ingress"
		d.CC = geo.lookup(d.Src)
	case out && !in:
		d.Dir = "egress"
		d.CC = geo.lookup(d.Dst)
	default:
		d.Dir = "forward"
		d.CC = geo.lookup(d.Src)
	}
	return d
}

func protoName(p byte) string {
	switch p {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	case 132:
		return "SCTP"
	default:
		return strconv.Itoa(int(p))
	}
}
