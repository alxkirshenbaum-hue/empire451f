package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestSSHWriter(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "lab")
	panel := filepath.Join(root, "panel")
	cfg := filepath.Join(root, "etc")
	lock := filepath.Join(root, "lock")
	for _, dir := range []string{state, panel, filepath.Join(cfg, "lab")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	run := "a9b5c248-884a-40f0-823a-4dae9a541e3b"
	auth := filepath.Join(cfg, "lab", "auth.caddy")
	write := func(path string, b []byte) {
		t.Helper()
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	baseline := []byte("synthetic fixture")
	write(auth, baseline)
	meta := map[string]any{"config": map[string]string{"id": "lab"}, "panel_generation": 1, "panel_run_id": run, "panel_auth_hash": fmt.Sprintf("%x", sha256.Sum256(baseline)), "files": map[string]string{}}
	b, _ := json.Marshal(meta)
	write(filepath.Join(state, "manifest.json"), b)
	key := bytes.Repeat([]byte{17}, 32)
	write(filepath.Join(panel, "vault.key"), key)
	cipher, _ := vault.New(key)
	path := filepath.Join(panel, "state.db")
	r, err := storage.Open(context.Background(), path, cipher, 1)
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	sqlExec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	sqlExec("INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'importing','{}','now','copy_handed_off')", run)
	sqlExec("INSERT INTO profile_templates VALUES('t','sfa','SFA','naive_https',1)")
	revision := func(id, date string) {
		sqlExec("INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at,approved_at) VALUES(?,'t',?,'sfa','1','{}','fixture','approved',?,?)", id, id, date, date)
	}
	revision("first", "2026-10-01")
	revision("latest", "2026-11-01")
	queue := func(login string) (storage.Receipt, error) {
		return queueFromInstallation(state, cfg, lock, panel, run, login)
	}
	if _, err := queue("Case"); err == nil {
		t.Fatal("copy handoff enabled create")
	}
	sqlExec("UPDATE legacy_migration_runs SET phase='verified_cutover',status='verified_cutover'")
	// Run the actual Python wrapper with synthetic paths, intercept only execv.
	py := `import pathlib, runpy, sys
from unittest.mock import patch
script, state, lock, run = sys.argv[1:]
source = pathlib.Path(script).read_text().replace('@STATE@',state).replace('/run/lock/empire-vpn.lock',lock)
with patch('os.geteuid',return_value=0), patch('builtins.input',return_value='Case'), patch('os.execv') as dispatch:
    exec(compile(source,script,'exec'),{'__name__':'__main__'})
    dispatch.assert_called_once_with('/usr/local/bin/vpnctl',['vpnctl','user','create','--installation','lab','--owner-run',run,'--login','Case'])
`
	if out, err := exec.Command("python3", "-B", "-c", py, "../../../templates/vpn-add-user", state, lock, run).CombinedOutput(); err != nil {
		t.Fatalf("wrapper: %v %s", err, out)
	}
	a, err := queue("Case")
	if err != nil {
		t.Fatal(err)
	}
	revision("new", "2026-12-01")
	replay, err := queue("Case")
	if err != nil || a != replay {
		t.Fatal("duplicate issuance", err)
	}
	lower, err := queue("case")
	if err != nil || a == lower {
		t.Fatal("lost exact case", err)
	}
	for id, want := range map[string]string{a.UserID: "latest", lower.UserID: "new"} {
		var got string
		if err := db.QueryRow("SELECT template_revision_id FROM user_profiles WHERE user_id=?", id).Scan(&got); err != nil || got != want {
			t.Fatal("wrong revision", err)
		}
	}
	write(auth, []byte("changed"))
	if _, err := queue("blocked"); err == nil {
		t.Fatal("ignored drift")
	}
	write(auth, baseline)
	write(filepath.Join(state, "pending.json"), []byte("{}"))
	if _, err := queue("blocked"); err == nil {
		t.Fatal("ignored pending transaction")
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM operations").Scan(&n); err != nil || n != 2 {
		t.Fatal("unexpected writes", err)
	}
}
