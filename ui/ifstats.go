// Interface statistics sampler for the SOC overview: a goroutine reads
// /proc/net/dev every sampleSecs into an in-memory ring buffer (one hour of
// history), and /api/ifstats serves per-interface in/out rates plus error
// counter deltas. One small procfile read per tick — no external tools, no
// disk writes, a few hundred KB of RAM.
package main

import (
	"bufio"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ifSampleSecs = 10
	// one hour of history plus one extra sample so the first delta is defined
	ifRingCap = 3600/ifSampleSecs + 1
)

// ifCounters holds the cumulative per-interface counters of one /proc/net/dev
// line (column order of the kernel's seq file).
type ifCounters struct {
	RxBytes, RxPackets, RxErrs, RxDrop, RxFifo, RxFrame            uint64
	TxBytes, TxPackets, TxErrs, TxDrop, TxFifo, TxColls, TxCarrier uint64
}

type ifSample struct {
	Ts int64
	C  map[string]ifCounters
}

type ifMeta struct {
	Up      bool
	Speed   int
	IfIndex int
	IfLink  int
	Bridge  bool
	Updated time.Time
}

var (
	ifMu   sync.Mutex
	ifRing []ifSample

	ifMetaMu sync.RWMutex
	ifMetaCache = make(map[string]ifMeta)
)

// parseNetDev parses /proc/net/dev content. Loopback is kept — the frontend
// decides what to show.
func parseNetDev(r io.Reader) map[string]ifCounters {
	out := map[string]ifCounters{}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		i := strings.IndexByte(line, ':')
		if i < 0 {
			continue // the two header lines
		}
		name := strings.TrimSpace(line[:i])
		f := strings.Fields(line[i+1:])
		if name == "" || len(f) < 16 {
			continue
		}
		n := make([]uint64, 16)
		for k := 0; k < 16; k++ {
			n[k], _ = strconv.ParseUint(f[k], 10, 64)
		}
		out[name] = ifCounters{
			RxBytes: n[0], RxPackets: n[1], RxErrs: n[2], RxDrop: n[3], RxFifo: n[4], RxFrame: n[5],
			TxBytes: n[8], TxPackets: n[9], TxErrs: n[10], TxDrop: n[11], TxFifo: n[12], TxColls: n[13], TxCarrier: n[14],
		}
	}
	return out
}

func sampleNetDev() {
	f, err := os.Open("/proc/net/dev")
	if err != nil {
		return // not Linux (dev box) — /api/ifstats just stays empty
	}
	c := parseNetDev(f)
	f.Close()
	if len(c) == 0 {
		return
	}
	ifMu.Lock()
	ifRing = append(ifRing, ifSample{Ts: time.Now().Unix(), C: c})
	if len(ifRing) > ifRingCap {
		ifRing = append([]ifSample(nil), ifRing[len(ifRing)-ifRingCap:]...)
	}
	ifMu.Unlock()
}

func startIfSampler() {
	sampleNetDev()
	go func() {
		t := time.NewTicker(ifSampleSecs * time.Second)
		for range t.C {
			sampleNetDev()
		}
	}()
}

// rate returns the per-second delta between two cumulative counter readings,
// clamped to 0 on counter reset (interface bounce, driver reload).
func rate(prev, cur uint64, dt int64) float64 {
	if dt <= 0 || cur < prev {
		return 0
	}
	return float64(cur-prev) / float64(dt)
}

func readSysNet(name, attr string) string {
	b, err := os.ReadFile("/sys/class/net/" + name + "/" + attr)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func procUint(path string) uint64 {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

// errSum totals every error-class counter — one number per tick for the
// error spark series (they are almost always flat zero).
func errSum(c ifCounters) uint64 {
	return c.RxErrs + c.RxDrop + c.RxFifo + c.RxFrame + c.TxErrs + c.TxDrop + c.TxFifo + c.TxColls + c.TxCarrier
}

// ifStats builds the /api/ifstats payload: per interface, the bps/pps series
// over the ring window, error deltas over the window, cumulative totals, and
// link metadata; plus the conntrack gauge for the SOC header.
func ifStats() map[string]interface{} {
	ifMu.Lock()
	ring := make([]ifSample, len(ifRing))
	copy(ring, ifRing)
	ifMu.Unlock()

	names := map[string]bool{}
	for _, s := range ring {
		for n := range s.C {
			names[n] = true
		}
	}
	var sorted []string
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)

	ifaces := []map[string]interface{}{}
	for _, name := range sorted {
		var rxBps, txBps, rxPps, txPps, errs []float64
		var errDelta ifCounters
		for i := 1; i < len(ring); i++ {
			prev, okP := ring[i-1].C[name]
			cur, okC := ring[i].C[name]
			if !okP || !okC {
				rxBps = append(rxBps, 0)
				txBps = append(txBps, 0)
				rxPps = append(rxPps, 0)
				txPps = append(txPps, 0)
				errs = append(errs, 0)
				continue
			}
			dt := ring[i].Ts - ring[i-1].Ts
			rxBps = append(rxBps, rate(prev.RxBytes, cur.RxBytes, dt)*8)
			txBps = append(txBps, rate(prev.TxBytes, cur.TxBytes, dt)*8)
			rxPps = append(rxPps, rate(prev.RxPackets, cur.RxPackets, dt))
			txPps = append(txPps, rate(prev.TxPackets, cur.TxPackets, dt))
			if es, ep := errSum(cur), errSum(prev); es > ep {
				errs = append(errs, float64(es-ep))
			} else {
				errs = append(errs, 0)
			}
			d := func(p, c uint64) uint64 {
				if c > p {
					return c - p
				}
				return 0
			}
			errDelta.RxErrs += d(prev.RxErrs, cur.RxErrs)
			errDelta.RxDrop += d(prev.RxDrop, cur.RxDrop)
			errDelta.RxFifo += d(prev.RxFifo, cur.RxFifo)
			errDelta.RxFrame += d(prev.RxFrame, cur.RxFrame)
			errDelta.TxErrs += d(prev.TxErrs, cur.TxErrs)
			errDelta.TxDrop += d(prev.TxDrop, cur.TxDrop)
			errDelta.TxFifo += d(prev.TxFifo, cur.TxFifo)
			errDelta.TxColls += d(prev.TxColls, cur.TxColls)
			errDelta.TxCarrier += d(prev.TxCarrier, cur.TxCarrier)
		}
		last := ring[len(ring)-1].C[name]

		ifMetaMu.RLock()
		meta, ok := ifMetaCache[name]
		ifMetaMu.RUnlock()
		if !ok || time.Since(meta.Updated) > 10*time.Second {
			speed := 0
			if s := readSysNet(name, "speed"); s != "" && s != "-1" {
				speed, _ = strconv.Atoi(s)
			}
			ifindex, _ := strconv.Atoi(readSysNet(name, "ifindex"))
			iflink, _ := strconv.Atoi(readSysNet(name, "iflink"))
			meta = ifMeta{
				Up:      readSysNet(name, "operstate") == "up",
				Speed:   speed,
				IfIndex: ifindex,
				IfLink:  iflink,
				Bridge:  readSysNet(name, "bridge/bridge_id") != "",
				Updated: time.Now(),
			}
			ifMetaMu.Lock()
			ifMetaCache[name] = meta
			ifMetaMu.Unlock()
		}

		ifaces = append(ifaces, map[string]interface{}{
			"name":       name,
			"up":         meta.Up,
			"speed_mbps": meta.Speed,
			"ifindex":    meta.IfIndex,
			"iflink":     meta.IfLink,
			"veth":       meta.IfLink != 0 && meta.IfLink != meta.IfIndex,
			"bridge":     meta.Bridge,
			"rx_bps":     rxBps,
			"tx_bps":     txBps,
			"rx_pps":     rxPps,
			"tx_pps":     txPps,
			"err_series": errs,
			"errors": map[string]uint64{
				"rx_errs": errDelta.RxErrs, "rx_drop": errDelta.RxDrop,
				"rx_fifo": errDelta.RxFifo, "rx_frame": errDelta.RxFrame,
				"tx_errs": errDelta.TxErrs, "tx_drop": errDelta.TxDrop,
				"tx_fifo": errDelta.TxFifo, "tx_colls": errDelta.TxColls,
				"tx_carrier": errDelta.TxCarrier,
			},
			"totals": map[string]uint64{
				"rx_bytes": last.RxBytes, "tx_bytes": last.TxBytes,
				"rx_packets": last.RxPackets, "tx_packets": last.TxPackets,
			},
			// cumulative since boot, for the error summary table
			"errors_total": map[string]uint64{
				"rx_errs": last.RxErrs, "rx_drop": last.RxDrop,
				"rx_fifo": last.RxFifo, "rx_frame": last.RxFrame,
				"tx_errs": last.TxErrs, "tx_drop": last.TxDrop,
				"tx_fifo": last.TxFifo, "tx_colls": last.TxColls,
				"tx_carrier": last.TxCarrier,
			},
		})
	}
	var ts []int64
	for i := 1; i < len(ring); i++ {
		ts = append(ts, ring[i].Ts)
	}
	return map[string]interface{}{
		"sample_secs": ifSampleSecs,
		"ts":          ts,
		"ifaces":      ifaces,
		"container":   kernelLogHidden(),
		"conntrack": map[string]uint64{
			"count": procUint("/proc/sys/net/netfilter/nf_conntrack_count"),
			"max":   procUint("/proc/sys/net/netfilter/nf_conntrack_max"),
		},
	}
}
