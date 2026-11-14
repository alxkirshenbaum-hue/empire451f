//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
)

func TestOwnerCLITransportAndPrivateDownload(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	session := filepath.Join(root, "session")
	const token = "synthetic-owner-cli-session"
	if err := os.WriteFile(session, []byte(token), 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(root, "api.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	var mutex sync.Mutex
	var requests [][]byte
	code := 200
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, e := r.Cookie("session")
		if e != nil || cookie.Value != token {
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == "POST" {
			if r.Header.Get("Origin") != auth.Origin || r.Header.Get("X-CSRF-Token") != auth.CSRF(token) || r.Header.Get("Idempotency-Key") != "00000000-0000-4000-8000-000000000001" {
				w.WriteHeader(403)
				return
			}
			raw, _ := io.ReadAll(r.Body)
			mutex.Lock()
			requests = append(requests, raw)
			mutex.Unlock()
			w.WriteHeader(202)
			fmt.Fprint(w, `{"data":{"operation_id":"00000000-0000-4000-8000-000000000002","user_id":"00000000-0000-4000-8000-000000000003"}}`)
			return
		}
		mutex.Lock()
		selected := code
		mutex.Unlock()
		if selected != 200 {
			w.WriteHeader(selected)
			fmt.Fprint(w, `{"error":{"code":"OPERATION_IN_PROGRESS","retryable":true}}`)
			return
		}
		if strings.Contains(r.URL.Path, "/profiles/download") {
			fmt.Fprint(w, `{"outbounds":[{"type":"naive","username":"Case","password":"synthetic-vpn-password"}]}`)
			return
		}
		fmt.Fprint(w, `{"data":{"users":[],"next_cursor":""}}`)
	})
	server := &http.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	t.Setenv("VPNCTL_SOCKET", socket)
	t.Setenv("VPNCTL_SESSION_FILE", session)
	invoke := func(want int, args ...string) (string, string) {
		t.Helper()
		var out, stderr bytes.Buffer
		if got := execute(args, &out, &stderr); got != want {
			t.Fatal("CLI exit", got, want)
		}
		if strings.Contains(out.String()+stderr.String(), token) || strings.Contains(out.String()+stderr.String(), "synthetic-vpn-password") {
			t.Fatal("CLI disclosed credential")
		}
		return out.String(), stderr.String()
	}
	invoke(0, "user", "list", "--json")
	args := []string{"user", "create", "--login", "Case", "--template", "00000000-0000-4000-8000-000000000004", "--client", "sfa-1.14.4", "--idempotency-key", "00000000-0000-4000-8000-000000000001", "--json"}
	invoke(0, args...)
	invoke(0, args...)
	mutex.Lock()
	if len(requests) != 2 || !bytes.Equal(requests[0], requests[1]) {
		t.Fatal("retry changed intent")
	}
	mutex.Unlock()
	invoke(2, "user", "list", "--ru-dm")
	invoke(2, "user", "create", "--login", "Case", "--template", "00000000-0000-4000-8000-000000000004")
	target := filepath.Join(root, "profile.json")
	invoke(0, "profile", "download", "00000000-0000-4000-8000-000000000003", "--output", target)
	info, err := os.Stat(target)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("profile mode", err)
	}
	original, err := os.ReadFile(target)
	if err != nil || !json.Valid(original) {
		t.Fatal("profile file")
	}
	defer clear(original)
	invoke(3, "profile", "download", "00000000-0000-4000-8000-000000000003", "--output", target)
	unchanged, err := os.ReadFile(target)
	if err != nil || !bytes.Equal(original, unchanged) {
		t.Fatal("overwrote existing profile")
	}
	clear(unchanged)
	invoke(2, "profile", "download", "00000000-0000-4000-8000-000000000003", "--output", filepath.Join(root, "unsupported.json"), "--ru-dm", "--acknowledge")
	mutex.Lock()
	code = 409
	mutex.Unlock()
	output, _ := invoke(4, "user", "list", "--json")
	if !strings.Contains(output, "OPERATION_IN_PROGRESS") {
		t.Fatal("JSON error envelope missing")
	}
}
