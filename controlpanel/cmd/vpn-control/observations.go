package main

import (
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

type resourceSample struct {
	State      string            `json:"state"`
	Source     string            `json:"source"`
	ObservedAt *time.Time        `json:"observed_at"`
	StaleAfter *time.Time        `json:"stale_after"`
	Values     map[string]uint64 `json:"values,omitempty"`
	Load1      *float64          `json:"load_average_1m,omitempty"`
}
type localResources struct {
	Scope   string         `json:"scope"`
	Memory  resourceSample `json:"memory"`
	Load    resourceSample `json:"load"`
	Storage resourceSample `json:"storage"`
	Note    string         `json:"note"`
}

func unknownResource(source string) resourceSample {
	return resourceSample{State: "unknown", Source: source}
}
func observedResource(source string, now time.Time) resourceSample {
	now = now.UTC()
	until := now.Add(time.Minute)
	return resourceSample{State: "observed", Source: source, ObservedAt: &now, StaleAfter: &until}
}
func (s resourceSample) freshness(now time.Time) string {
	if s.State != "observed" || s.ObservedAt == nil || s.StaleAfter == nil || now.Before(*s.ObservedAt) {
		return "unknown"
	}
	if !now.Before(*s.StaleAfter) {
		return "stale"
	}
	return "observed"
}
func observeResources(directory string, now time.Time) localResources {
	out := localResources{Scope: "local_ingress", Memory: unknownResource("linux_proc_meminfo"), Load: unknownResource("linux_proc_loadavg"), Storage: unknownResource("registry_filesystem_statfs"), Note: "Local OS observations only. Load average is not CPU percent; registry files are not total panel footprint. No VPN or exit health is inferred."}
	collectLocalResources(&out, directory, now)
	return out
}
func boundedResourceFile(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 65537))
	if len(b) > 65536 {
		return nil, os.ErrInvalid
	}
	return b, e
}
func parseMemory(raw []byte) (map[string]uint64, bool) {
	values := map[string]uint64{}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 3 && (f[0] == "MemTotal:" || f[0] == "MemAvailable:") {
			if f[2] != "kB" {
				return nil, false
			}
			n, e := strconv.ParseUint(f[1], 10, 64)
			if e != nil || n > ^uint64(0)/1024 {
				return nil, false
			}
			values[strings.TrimSuffix(f[0], ":")] = n * 1024
		}
	}
	total, t := values["MemTotal"]
	available, a := values["MemAvailable"]
	if !t || !a || total == 0 || available > total {
		return nil, false
	}
	return map[string]uint64{"total_bytes": total, "available_bytes": available}, true
}
