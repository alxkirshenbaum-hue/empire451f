package main

import (
	"bytes"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAuthWhoamiUnixTransport(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	session := filepath.Join(dir, "session")
	os.WriteFile(session, []byte("identity-private-token"), 0600)
	t.Setenv("VPNCTL_SESSION_FILE", session)
	sock := filepath.Join(dir, "api.sock")
	t.Setenv("VPNCTL_SOCKET", sock)
	listener, e := net.Listen("unix", sock)
	if e != nil {
		t.Fatal(e)
	}
	valid := make(chan bool, 1)
	srv := http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, e := r.Cookie("session")
		valid <- r.Method == "GET" && r.URL.Path == "/api/v1/auth/me" && e == nil && cookie.Value == "identity-private-token"
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"data":{"username":"ExactOwnerCase","role":"owner","expires_at":"2030-01-01 00:00:00"}}`))
	})}
	go srv.Serve(listener)
	defer srv.Close()
	var out, stderr bytes.Buffer
	if code := execute([]string{"auth", "whoami"}, &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	if !<-valid {
		t.Fatal("invalid transport")
	}
	if !strings.Contains(out.String(), "ExactOwnerCase") || strings.Contains(out.String()+stderr.String(), "identity-private-token") {
		t.Fatal("unsafe identity output")
	}
}
func TestAuthWhoamiMissingSession(t *testing.T) {
	t.Setenv("VPNCTL_SESSION_FILE", "")
	var out, stderr bytes.Buffer
	if code := execute([]string{"auth", "whoami"}, &out, &stderr); code != 3 || out.Len() != 0 {
		t.Fatal(code, out.String())
	}
}
