package main

import "testing"

func TestConfiguredOriginEnvironment(t *testing.T) {
	t.Setenv("PANEL_ORIGIN", "https://example.com")
	if origin, err := configuredOrigin(); err != nil || origin != "https://example.com" {
		t.Fatal(origin, err)
	}
	for _, value := range []string{"", "https://example.com/", "http://example.com", "https://example.com:443"} {
		t.Setenv("PANEL_ORIGIN", value)
		if _, err := configuredOrigin(); err == nil {
			t.Fatalf("accepted %q", value)
		}
	}
}
