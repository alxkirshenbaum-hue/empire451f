//go:build linux

package main

import (
	"bytes"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnerCLIResources(t *testing.T) {
	root := t.TempDir()
	os.Chmod(root, 0700)
	socket := filepath.Join(root, "api.sock")
	session := filepath.Join(root, "session")
	if e := os.WriteFile(session, []byte("resource-test-session"), 0600); e != nil {
		t.Fatal(e)
	}
	listener, e := net.Listen("unix", socket)
	if e != nil {
		t.Fatal(e)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, e := r.Cookie("session")
		if e != nil || cookie.Value != "resource-test-session" || r.Method != "GET" || r.URL.Path != "/api/v1/system/resources" {
			http.Error(w, "refused", 403)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"data":{"scope":"local_ingress","memory":{"state":"unknown"},"load":{"state":"unknown"},"storage":{"state":"unknown"}}}`)
	})}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	t.Setenv("VPNCTL_SOCKET", socket)
	t.Setenv("VPNCTL_SESSION_FILE", session)
	var out, stderr bytes.Buffer
	if code := execute([]string{"system", "resources", "--json"}, &out, &stderr); code != 0 {
		t.Fatal(code, stderr.String())
	}
	if !strings.Contains(out.String(), "local_ingress") || strings.Contains(out.String(), "resource-test-session") {
		t.Fatal("missing or unsafe resource response")
	}
}
