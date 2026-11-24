package main

import (
	"strconv"
	"strings"
	"time"
)

type networkCounters struct {
	Bytes   uint64 `json:"bytes"`
	Packets uint64 `json:"packets"`
	Errors  uint64 `json:"errors"`
	Dropped uint64 `json:"dropped"`
}
type networkInterface struct {
	Name     string          `json:"name"`
	Receive  networkCounters `json:"receive"`
	Transmit networkCounters `json:"transmit"`
}

// Linux aggregates user/nice/system/idle/iowait/irq/softirq/steal. Guest and
// guest_nice are already included in user/nice and must not be added again.
func parseCPU(raw []byte) ([8]uint64, bool) {
	var result [8]uint64
	first := strings.SplitN(string(raw), "\n", 2)[0]
	fields := strings.Fields(first)
	if len(fields) < 5 || len(fields) > 11 || fields[0] != "cpu" {
		return result, false
	}
	for i, field := range fields[1:] {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return result, false
		}
		if i < len(result) {
			result[i] = value
		}
	}
	return result, true
}
func cpuPercent(before, after [8]uint64) (float64, bool) {
	var total, idle uint64
	for i := range before {
		if after[i] < before[i] {
			return 0, false
		}
		delta := after[i] - before[i]
		if delta > ^uint64(0)-total {
			return 0, false
		}
		total += delta
		if i == 3 || i == 4 {
			idle += delta
		}
	}
	if total == 0 {
		return 0, false
	}
	return float64(total-idle) / float64(total) * 100, true
}
func observeCPU(read func(string) ([]byte, error), pause func(time.Duration), now time.Time) resourceSample {
	unknown := unknownResource("linux_proc_stat_interval")
	raw, err := read("/proc/stat")
	if err != nil {
		return unknown
	}
	before, ok := parseCPU(raw)
	if !ok {
		return unknown
	}
	started := time.Now()
	pause(100 * time.Millisecond)
	raw, err = read("/proc/stat")
	elapsed := time.Since(started)
	if err != nil || elapsed <= 0 {
		return unknown
	}
	after, ok := parseCPU(raw)
	if !ok {
		return unknown
	}
	percent, ok := cpuPercent(before, after)
	if !ok {
		return unknown
	}
	sample := observedResource("linux_proc_stat_interval", now.Add(elapsed))
	sample.UsagePercent = &percent
	sample.IntervalMS = uint64(elapsed / time.Millisecond)
	return sample
}
func parseNetwork(raw []byte) ([]networkInterface, bool) {
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) < 3 || !strings.Contains(lines[0], "Inter-") || !strings.Contains(lines[1], "bytes") {
		return nil, false
	}
	result := make([]networkInterface, 0, len(lines)-2)
	seen := map[string]bool{}
	for _, line := range lines[2:] {
		colon := strings.LastIndexByte(line, ':')
		if colon < 1 || len(result) >= 256 {
			return nil, false
		}
		name := strings.TrimSpace(line[:colon])
		if name == "" || len(name) > 15 || strings.ContainsAny(name, " \t\r\n/") || seen[name] {
			return nil, false
		}
		seen[name] = true
		fields := strings.Fields(line[colon+1:])
		if len(fields) != 16 {
			return nil, false
		}
		var counters [16]uint64
		for i, field := range fields {
			value, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				return nil, false
			}
			counters[i] = value
		}
		result = append(result, networkInterface{Name: name, Receive: networkCounters{counters[0], counters[1], counters[2], counters[3]}, Transmit: networkCounters{counters[8], counters[9], counters[10], counters[11]}})
	}
	return result, true
}
