package main

import (
	"bytes"
	"encoding/json"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthPasswdProtectedPromptAndSession(t *testing.T) {
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	session := filepath.Join(dir, "session")
	if e := os.WriteFile(session, []byte("fixture-token"), 0600); e != nil {
		t.Fatal(e)
	}
	// Synthetic test values are returned by the interactive prompt, never passed as arguments.
	script := "#!/bin/sh\n[ \"$#\" = 1 ] || exit 1\ncase \"$1\" in\n 'Current panel owner password:') echo 'old synthetic password';;\n 'New panel owner password:'|'Repeat new panel owner password:') echo 'new synthetic password';;\n *) exit 1;;\nesac\n"
	if e := os.WriteFile(filepath.Join(dir, "systemd-ask-password"), []byte(script), 0700); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	t.Setenv("VPNCTL_SESSION_FILE", session)
	sock := filepath.Join(dir, "api.sock")
	t.Setenv("VPNCTL_SOCKET", sock)
	listener, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	requests := make(chan bool, 1)
	server := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var input map[string]string
		err := json.NewDecoder(r.Body).Decode(&input)
		c, ce := r.Cookie("session")
		valid := err == nil && ce == nil && c.Value == "fixture-token" && r.URL.Path == "/api/v1/auth/change-password" && r.Header.Get("Origin") == auth.Origin && r.Header.Get("X-CSRF-Token") == auth.CSRF("fixture-token") && input["old_password"] == "old synthetic password" && input["new_password"] == "new synthetic password" && input["confirm_password"] == "new synthetic password"
		requests <- valid
		if !valid {
			w.WriteHeader(400)
			return
		}
		w.WriteHeader(204)
	})}
	go server.Serve(listener)
	defer server.Close()
	var stderr bytes.Buffer
	if code := authCommand([]string{"passwd"}, &stderr); code != 0 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if !<-requests {
		t.Fatal("invalid transport")
	}
	if _, e = os.Stat(session); !os.IsNotExist(e) {
		t.Fatal("obsolete session retained")
	}
	if strings.Contains(stderr.String(), "synthetic password") {
		t.Fatal("credential leaked")
	}
}
func TestAuthPasswdRejectsPasswordArguments(t *testing.T) {
	var stderr bytes.Buffer
	if code := authCommand([]string{"passwd", "secret-argument"}, &stderr); code != 2 {
		t.Fatal(code)
	}
	if strings.Contains(stderr.String(), "secret-argument") {
		t.Fatal("argument leaked")
	}
}
