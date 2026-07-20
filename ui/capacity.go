package main

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var softnetPrev struct {
	sync.Mutex
	dropped, squeezed uint64
	at                time.Time
}

func softnetStatus() map[string]interface{} {
	f, err := os.Open("/proc/net/softnet_stat")
	if err != nil {
		return map[string]interface{}{}
	}
	defer f.Close()
	var dropped, squeezed uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 {
			continue
		}
		d, _ := strconv.ParseUint(fields[1], 16, 64)
		s, _ := strconv.ParseUint(fields[2], 16, 64)
		dropped += d
		squeezed += s
	}
	now := time.Now()
	softnetPrev.Lock()
	defer softnetPrev.Unlock()
	dr, sr := 0.0, 0.0
	if !softnetPrev.at.IsZero() {
		if dt := now.Sub(softnetPrev.at).Seconds(); dt > 0 {
			dr = float64(dropped-softnetPrev.dropped) / dt
			sr = float64(squeezed-softnetPrev.squeezed) / dt
		}
	}
	softnetPrev.dropped, softnetPrev.squeezed, softnetPrev.at = dropped, squeezed, now
	return map[string]interface{}{"dropped": dropped, "squeezed": squeezed, "droppedPerSecond": dr, "squeezedPerSecond": sr}
}

func procKeyValues(path string) map[string]uint64 {
	out := map[string]uint64{}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	for sc := bufio.NewScanner(f); sc.Scan(); {
		fields := strings.Fields(strings.TrimSuffix(sc.Text(), ":"))
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		// meminfo reports KiB; sockstat and other proc files use native counts.
		if strings.HasSuffix(path, "meminfo") {
			value *= 1024
		}
		out[key] = value
	}
	return out
}

func sockstat() map[string]map[string]uint64 {
	out := map[string]map[string]uint64{}
	for _, path := range []string{"/proc/net/sockstat", "/proc/net/sockstat6"} {
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) < 3 {
				continue
			}
			name := strings.TrimSuffix(strings.ToLower(fields[0]), ":")
			if path[len(path)-1] == '6' {
				name += "6"
			}
			values := map[string]uint64{}
			for i := 1; i+1 < len(fields); i += 2 {
				values[fields[i]], _ = strconv.ParseUint(fields[i+1], 10, 64)
			}
			out[name] = values
		}
		f.Close()
	}
	return out
}

func systemdUnit(unit string) map[string]string {
	out, _ := run("systemctl", "show", unit, "-p", "ActiveState", "-p", "SubState", "-p", "Result", "-p", "Type", "-p", "MemoryCurrent", "-p", "CPUUsageNSec", "-p", "TasksCurrent")
	values := map[string]string{"unit": unit}
	for _, line := range strings.Split(out, "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			values[key] = value
		}
	}
	return values
}

// capacityStatus exposes the traffic-exhaustible kernel resources alongside the
// current service state. It intentionally reports TCP/UDP as socket pressure,
// because Linux does not impose one universal TCP/UDP connection limit.
func capacityStatus() map[string]interface{} {
	mem := procKeyValues("/proc/meminfo")
	load := strings.Fields(readFileStr("/proc/loadavg"))
	fileNr := strings.Fields(readFileStr("/proc/sys/fs/file-nr"))
	files := map[string]uint64{}
	if len(fileNr) >= 3 {
		files["allocated"], _ = strconv.ParseUint(fileNr[0], 10, 64)
		files["max"], _ = strconv.ParseUint(fileNr[2], 10, 64)
	}
	disk := map[string]uint64{}
	var stat syscall.Statfs_t
	if syscall.Statfs(filepath.Clean(stateDir), &stat) == nil {
		disk["total"] = stat.Blocks * uint64(stat.Bsize)
		disk["available"] = stat.Bavail * uint64(stat.Bsize)
		disk["used"] = disk["total"] - disk["available"]
	}
	return map[string]interface{}{
		"memory":    map[string]uint64{"total": mem["MemTotal"], "available": mem["MemAvailable"], "used": mem["MemTotal"] - mem["MemAvailable"], "swapTotal": mem["SwapTotal"], "swapFree": mem["SwapFree"]},
		"conntrack": map[string]uint64{"count": procUint("/proc/sys/net/netfilter/nf_conntrack_count"), "max": procUint("/proc/sys/net/netfilter/nf_conntrack_max")},
		"files":     files, "disk": disk, "sockets": sockstat(), "softnet": softnetStatus(), "load": load,
		"services": []map[string]string{systemdUnit("nftgeo.service"), systemdUnit("nftgeo-ui.service"), systemdUnit("nftgeo.timer")},
	}
}
