package main

import (
	"bytes"
	"context"
	"database/sql"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestLoginReadLogout(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	path := filepath.Join(dir, "state.db")
	key, err := vault.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := storage.Open(ctx, path, key, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	s, err := auth.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err = s.Bootstrap(ctx, "fixture", "synthetic cli password"); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var owner string
	if err = db.QueryRow("SELECT id FROM admin_accounts").Scan(&owner); err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec("INSERT INTO profile_templates VALUES('t','sfa','SFA','naive_https',1); INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at) VALUES('r','t','1','sfa','1','{}','test','approved','now')")
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := reg.QueueCreate(ctx, owner, "a9b5c248-884a-40f0-823a-4dae9a541e3b", storage.CreateRequest{Login: "fixture", DisplayName: "fixture", TemplateRevisionID: "r", TargetClient: "sfa"})
	if err != nil {
		t.Fatal(err)
	}
	reader, err := status.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	sock := filepath.Join(dir, "api.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := http.Server{Handler: s.Handler(reader.Handler())}
	go srv.Serve(l)
	defer srv.Close()
	session := filepath.Join(dir, "session")
	t.Setenv("VPNCTL_SOCKET", sock)
	t.Setenv("VPNCTL_SESSION_FILE", session)
	// Replace only the interactive password prompt for this CLI test.
	if err = os.WriteFile(filepath.Join(dir, "systemd-ask-password"), []byte("#!/bin/sh\necho 'synthetic cli password'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+":"+os.Getenv("PATH"))
	run := func(want int, args ...string) {
		t.Helper()
		var out, stderr bytes.Buffer
		if got := execute(args, &out, &stderr); got != want {
			t.Fatalf("exit %d want %d (%s)", got, want, stderr.String())
		}
	}
	run(0, "auth", "login", "fixture")
	old, err := os.ReadFile(session)
	if err != nil {
		t.Fatal(err)
	}
	run(0, "operation", "show", receipt.OperationID, "--quiet")
	run(0, "auth", "logout")
	if _, err = os.Stat(session); !os.IsNotExist(err) {
		t.Fatal("session file remains")
	}
	if err = os.WriteFile(session, old, 0600); err != nil {
		t.Fatal(err)
	}
	run(3, "operation", "show", receipt.OperationID, "--quiet")
}
