package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestObservationMemoryAndFreshness(t *testing.T) {
	for _, raw := range []string{"", "MemTotal: 10 kB\n", "MemTotal: 1 kB\nMemAvailable: 2 kB", "MemTotal: -1 kB\nMemAvailable: 1 kB", "MemTotal: 10 MB\nMemAvailable: 2 kB"} {
		if _, ok := parseMemory([]byte(raw)); ok {
			t.Fatalf("invalid memory accepted %q", raw)
		}
	}
	values, ok := parseMemory([]byte("MemTotal: 10 kB\nMemAvailable: 2 kB\n"))
	if !ok || values["total_bytes"] != 10240 || values["available_bytes"] != 2048 {
		t.Fatal(values)
	}
	now := time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC)
	s := observedResource("fixture", now)
	if s.freshness(now) != "observed" || s.freshness(now.Add(time.Minute)) != "stale" || s.freshness(now.Add(-time.Second)) != "unknown" {
		t.Fatal("invalid freshness")
	}
	if unknownResource("fixture").freshness(now) != "unknown" {
		t.Fatal("missing data trusted")
	}
}
func TestObservationUnknownDoesNotExposeErrorsOrPaths(t *testing.T) {
	sample := observeResources("/nonexistent/private/registry-password-fixture", time.Now())
	raw, e := json.Marshal(sample)
	if e != nil {
		t.Fatal(e)
	}
	if sample.Storage.State != "unknown" || sample.Storage.Values != nil {
		t.Fatal("missing filesystem reported")
	}
	var payload any
	if e = json.Unmarshal(raw, &payload); e != nil {
		t.Fatal(e)
	}
	var check func(any)
	check = func(value any) {
		switch value := value.(type) {
		case map[string]any:
			for key, child := range value {
				// Network counters legitimately use numeric "errors". Diagnostic
				// fields and diagnostic text must still never be returned.
				switch key {
				case "error", "error_message", "path", "detail":
					t.Fatal("diagnostic field exposed")
				}
				check(child)
			}
		case []any:
			for _, child := range value {
				check(child)
			}
		case string:
			for _, forbidden := range []string{"private", "password", "error"} {
				if strings.Contains(strings.ToLower(value), forbidden) {
					t.Fatal("private or diagnostic text exposed")
				}
			}
		}
	}
	check(payload)
}
