package main

import (
	"strings"
	"testing"
)

func TestProfileFilenameSafeFallback(t *testing.T) {
	for _, login := range []string{"../bad/name", "bad\r\nheader", "", strings.Repeat("a", 65), "名字"} {
		if got := profileFilename(login, "trusted-id", ""); got != "vpn-trusted-id.json" {
			t.Fatal(got)
		}
	}
	if got := profileFilename("Alice.Exact@example", "id", "sfa-1.15-alpha13"); got != "vpn-Alice.Exact@example-sfa-1.15-alpha13.json" {
		t.Fatal(got)
	}
}
