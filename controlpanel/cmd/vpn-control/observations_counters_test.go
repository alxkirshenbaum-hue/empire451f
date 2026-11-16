package main

import (
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"
)

func TestObservationCPUInterval(t *testing.T) {
	before, ok := parseCPU([]byte("cpu 10 0 10 50 10 0 0 0 6 0\ncpu0 0"))
	if !ok {
		t.Fatal("before")
	}
	after, ok := parseCPU([]byte("cpu 30 0 20 100 30 0 0 0 20 0\n"))
	percent, valid := cpuPercent(before, after)
	if !ok || !valid || math.Abs(percent-30) > 0.00001 {
		t.Fatalf("guest counted twice or idle/iowait busy: %v %v", percent, valid)
	}
	if _, ok = cpuPercent(before, before); ok {
		t.Fatal("zero interval accepted")
	}
	after[0] = 9
	if _, ok = cpuPercent(before, after); ok {
		t.Fatal("counter reset accepted")
	}
	if _, ok = cpuPercent([8]uint64{}, [8]uint64{^uint64(0), 1}); ok {
		t.Fatal("overflow accepted")
	}
	for _, raw := range []string{"", "cpu0 1 2 3 4", "cpu 1 2 3", "cpu -1 0 0 1", "cpu 18446744073709551616 0 0 1", "cpu 1 2 3 4 nope"} {
		if _, ok := parseCPU([]byte(raw)); ok {
			t.Fatalf("invalid CPU %q", raw)
		}
	}
	now := time.Now()
	reads := 0
	sample := observeCPU(func(path string) ([]byte, error) {
		if path != "/proc/stat" {
			t.Fatal("arbitrary path")
		}
		reads++
		if reads == 1 {
			return []byte("cpu 0 0 0 0"), nil
		}
		return []byte("cpu 1 0 0 3"), nil
	}, func(d time.Duration) {
		if d != 100*time.Millisecond {
			t.Fatal(d)
		}
		time.Sleep(time.Millisecond)
	}, now)
	if reads != 2 || sample.State != "observed" || sample.UsagePercent == nil || *sample.UsagePercent != 25 || sample.Source != "linux_proc_stat_interval" || sample.IntervalMS < 1 || sample.freshness(now.Add(time.Second)) != "observed" {
		t.Fatalf("bad sample %+v", sample)
	}
	for _, failure := range []int{1, 2} {
		reads = 0
		sample = observeCPU(func(string) ([]byte, error) {
			reads++
			if reads == failure {
				return nil, errors.New("private-secret")
			}
			return []byte("cpu 0 0 0 1"), nil
		}, func(time.Duration) {}, now)
		raw, _ := json.Marshal(sample)
		if sample.State != "unknown" || sample.UsagePercent != nil || strings.Contains(string(raw), "private") {
			t.Fatalf("failure trusted/leaked: %s", raw)
		}
	}
}
func TestObservationNetworkNamespaceCounters(t *testing.T) {
	header := "Inter-| Receive | Transmit\n face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed\n"
	rows := " lo: 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0\n eth0: 100 2 3 4 5 6 7 8 900 10 11 12 13 14 15 16\n"
	got, ok := parseNetwork([]byte(header + rows))
	if !ok || len(got) != 2 || got[0].Name != "lo" || got[0].Receive.Bytes != 0 || got[1].Receive.Bytes != 100 || got[1].Receive.Dropped != 4 || got[1].Transmit.Bytes != 900 || got[1].Transmit.Errors != 11 {
		t.Fatalf("bad counters %+v %v", got, ok)
	}
	for _, raw := range []string{"", header, header + "eth0: 1 2", header + strings.ReplaceAll(rows, "900", "-1"), header + strings.ReplaceAll(rows, "900", "18446744073709551616"), header + strings.ReplaceAll(rows, "eth0", "lo"), header + strings.Repeat("a", 16) + ": 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0"} {
		if _, ok := parseNetwork([]byte(raw)); ok {
			t.Fatalf("invalid network accepted %q", raw)
		}
	}
}
