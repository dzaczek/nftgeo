package main

import (
	"strings"
	"testing"
	"time"
)

const netDevFixture = `Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1721821    3419    0    0    0     0          0         0  1721821    3419    0    0    0     0       0          0
  eth0: 550632829  505709    2    7    0     3          0       333 42346475  305094    1    4    0     5       6          0
`

func TestParseNetDev(t *testing.T) {
	m := parseNetDev(strings.NewReader(netDevFixture))
	if len(m) != 2 {
		t.Fatalf("want 2 ifaces, got %d", len(m))
	}
	e := m["eth0"]
	if e.RxBytes != 550632829 || e.RxPackets != 505709 || e.RxErrs != 2 || e.RxDrop != 7 || e.RxFrame != 3 {
		t.Errorf("eth0 rx parsed wrong: %+v", e)
	}
	if e.TxBytes != 42346475 || e.TxPackets != 305094 || e.TxErrs != 1 || e.TxDrop != 4 || e.TxColls != 5 || e.TxCarrier != 6 {
		t.Errorf("eth0 tx parsed wrong: %+v", e)
	}
	if m["lo"].RxBytes != 1721821 {
		t.Errorf("lo rx parsed wrong: %+v", m["lo"])
	}
}

func TestRate(t *testing.T) {
	if r := rate(100, 200, 10); r != 10 {
		t.Errorf("rate(100,200,10)=%v want 10", r)
	}
	if r := rate(200, 100, 10); r != 0 { // counter reset clamps to 0
		t.Errorf("counter reset: got %v want 0", r)
	}
	if r := rate(100, 200, 0); r != 0 { // zero dt guards div-by-zero
		t.Errorf("zero dt: got %v want 0", r)
	}
}

func TestIfStatsSeries(t *testing.T) {
	ifMu.Lock()
	saved := ifRing
	ifRing = []ifSample{
		{Ts: 1000, C: map[string]ifCounters{"eth0": {RxBytes: 0, TxBytes: 0}}},
		{Ts: 1010, C: map[string]ifCounters{"eth0": {RxBytes: 1250, TxBytes: 2500, RxDrop: 3}}},
		{Ts: 1020, C: map[string]ifCounters{"eth0": {RxBytes: 2500, TxBytes: 2500, RxDrop: 3, TxErrs: 1}}},
	}
	ifMu.Unlock()
	defer func() { ifMu.Lock(); ifRing = saved; ifMu.Unlock() }()

	st := ifStats()
	ifaces := st["ifaces"].([]map[string]interface{})
	if len(ifaces) != 1 {
		t.Fatalf("want 1 iface, got %d", len(ifaces))
	}
	e := ifaces[0]
	rx := e["rx_bps"].([]float64)
	if len(rx) != 2 || rx[0] != 1000 || rx[1] != 1000 { // 1250 B / 10 s * 8
		t.Errorf("rx_bps = %v, want [1000 1000]", rx)
	}
	tx := e["tx_bps"].([]float64)
	if tx[0] != 2000 || tx[1] != 0 {
		t.Errorf("tx_bps = %v, want [2000 0]", tx)
	}
	errs := e["errors"].(map[string]uint64)
	if errs["rx_drop"] != 3 || errs["tx_errs"] != 1 {
		t.Errorf("error deltas = %v", errs)
	}
	es := e["err_series"].([]float64)
	if len(es) != 2 || es[0] != 3 || es[1] != 1 {
		t.Errorf("err_series = %v, want [3 1]", es)
	}
}

func TestIPHistogram(t *testing.T) {
	statsMu.Lock()
	saved := statsData
	now := time.Now().Unix()
	statsData = []statsEntry{
		{Ts: now - 3500, Src: "1.2.3.4", CC: "cn"},
		{Ts: now - 100, Src: "1.2.3.4", CC: "cn"},
		{Ts: now - 50, Src: "1.2.3.4", CC: "cn"},
		{Ts: now - 60, Src: "5.6.7.8", CC: "ru"},
		{Ts: now - 7200, Src: "9.9.9.9", CC: "us"}, // outside window
	}
	statsMu.Unlock()
	defer func() { statsMu.Lock(); statsData = saved; statsMu.Unlock() }()

	res := ipHistogram(0, 30, 10)
	ips := res["ips"].([]map[string]interface{})
	if len(ips) != 2 {
		t.Fatalf("want 2 ips, got %d", len(ips))
	}
	if ips[0]["ip"] != "1.2.3.4" || ips[0]["hits"] != 3 {
		t.Errorf("top ip = %v", ips[0])
	}
	b := ips[0]["buckets"].([]int)
	total := 0
	for _, n := range b {
		total += n
	}
	if len(b) != 30 || total != 3 {
		t.Errorf("buckets len=%d total=%d, want 30/3", len(b), total)
	}
	// recent hits land in the last bucket, the old one near the first
	if b[len(b)-1] != 2 {
		t.Errorf("last bucket = %d, want 2", b[len(b)-1])
	}
}
