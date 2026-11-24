//go:build linux

package main

import (
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func collectLocalResources(out *localResources, directory string, now time.Time) {
	out.CPU = observeCPU(boundedResourceFile, time.Sleep, now)
	if b, e := boundedResourceFile("/proc/net/dev"); e == nil {
		if interfaces, ok := parseNetwork(b); ok {
			out.Network = observedResource("linux_proc_net_dev", now)
			out.Network.Namespace = "collector_process_network_namespace"
			out.Network.Interfaces = interfaces
		}
	}
	if b, e := boundedResourceFile("/proc/meminfo"); e == nil {
		if values, ok := parseMemory(b); ok {
			out.Memory = observedResource("linux_proc_meminfo", now)
			out.Memory.Values = values
		}
	}
	if b, e := boundedResourceFile("/proc/loadavg"); e == nil {
		f := strings.Fields(string(b))
		if len(f) > 0 {
			n, e := strconv.ParseFloat(f[0], 64)
			if e == nil && n >= 0 && !math.IsNaN(n) && !math.IsInf(n, 0) {
				out.Load = observedResource("linux_proc_loadavg", now)
				out.Load.Load1 = &n
			}
		}
	}
	if directory == "" {
		return
	}
	var fs syscall.Statfs_t
	if e := syscall.Statfs(directory, &fs); e != nil || fs.Bsize <= 0 {
		return
	}
	block := uint64(fs.Bsize)
	if fs.Blocks > ^uint64(0)/block || fs.Bavail > ^uint64(0)/block {
		return
	}
	values := map[string]uint64{"filesystem_total_bytes": fs.Blocks * block, "filesystem_available_bytes": fs.Bavail * block}
	var allocated uint64
	complete := true
	for _, name := range []string{"state.db", "state.db-wal", "state.db-shm"} {
		i, e := os.Lstat(filepath.Join(directory, name))
		if os.IsNotExist(e) && name != "state.db" {
			continue
		}
		if e != nil || !i.Mode().IsRegular() {
			complete = false
			break
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok || st.Blocks < 0 || uint64(st.Blocks) > (^uint64(0)-allocated)/512 {
			complete = false
			break
		}
		allocated += uint64(st.Blocks) * 512
	}
	if complete {
		values["registry_allocated_bytes"] = allocated
	}
	out.Storage = observedResource("registry_filesystem_statfs", now)
	out.Storage.Values = values
}
