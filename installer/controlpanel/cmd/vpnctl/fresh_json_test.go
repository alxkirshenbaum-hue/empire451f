package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestFreshInstallerJSONPreservesImportedMaster(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if e := os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	output, e := exec.Command("python3", "-B", "../../../tests/fresh_json_fixture.py", dir).Output()
	if e != nil {
		t.Fatal("installer JSON fixture failed", e)
	}
	var receipt struct {
		Snapshot  string `json:"snapshot"`
		SourceSHA string `json:"source_sha256"`
	}
	if e = json.Unmarshal(output, &receipt); e != nil {
		t.Fatal(e)
	}
	input := filepath.Join(dir, "input.json")
	source, e := os.ReadFile(input)
	if e != nil {
		t.Fatal(e)
	}
	sourceHash := sha256.Sum256(source)
	key := bytes.Repeat([]byte{137}, 32)
	cipher, e := vault.New(key)
	if e != nil {
		t.Fatal(e)
	}
	dbPath := filepath.Join(dir, "state.db")
	keyPath := filepath.Join(dir, "key")
	if e = os.WriteFile(keyPath, key, 0600); e != nil {
		t.Fatal(e)
	}
	reg, e := storage.Open(ctx, dbPath, cipher, 1)
	if e != nil {
		t.Fatal(e)
	}
	reg.Close()
	db, e := sql.Open("sqlite3", dbPath)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = db.Exec("INSERT INTO admin_accounts VALUES('fresh-owner','fresh-owner','fresh-owner-hash',0,'now',NULL)"); e != nil {
		t.Fatal(e)
	}
	db.Close()
	inspect := func(extra ...string) map[string]any {
		t.Helper()
		args := append([]string{"-B", "../../../inspect_legacy.py", receipt.Snapshot, "--registry", dbPath}, extra...)
		raw, e := exec.Command("python3", args...).Output()
		if e != nil {
			t.Fatal("inspection/plan refused", e)
		}
		var obj map[string]any
		if e = json.Unmarshal(raw, &obj); e != nil {
			t.Fatal(e)
		}
		return obj
	}
	run := inspect()["run_id"].(string)
	inspect("--plan", run)
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"migration", "execute", "--approved-plan", run, "--staging-db", dbPath, "--snapshot", receipt.Snapshot, "--vault-key-file", keyPath}, &stdout, &stderr); code != 0 {
		t.Fatal("existing StageLegacy failed", code)
	}
	installation := filepath.Join(dir, "installation")
	os.Mkdir(installation, 0700)
	entries, e := os.ReadDir(receipt.Snapshot)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range entries {
		b, e := os.ReadFile(filepath.Join(receipt.Snapshot, entry.Name()))
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(installation, entry.Name()), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = exec.Command("python3", "-B", "../../../handoff_legacy.py", "--snapshot", receipt.Snapshot, "--installation-copy", installation, "--staging-db", dbPath, "--approved-plan", run).Output(); e != nil {
		t.Fatal("existing copy handoff refused", e)
	}
	db, e = sql.Open("sqlite3", dbPath)
	if e != nil {
		t.Fatal(e)
	}
	// Model only the already-tested runtime caller proof. This is a local storage/
	// copy-journal compatibility test, not another real Caddy/network acceptance.
	ref := "fresh-json-local-proof"
	if _, e = db.Exec("UPDATE legacy_migration_runs SET status='working_handed_off',report_ref=? WHERE id=?", ref, run); e != nil {
		t.Fatal(e)
	}
	db.Close()
	reg, e = storage.Open(ctx, dbPath, cipher, 1)
	if e != nil {
		t.Fatal(e)
	}
	expected := map[string]string{"Alice": "Synthetic Alice exact Case", "master_user": "Synthetic master imported unchanged"}
	seen := map[string]bool{}
	_, e = reg.CompleteLegacyCutover(ctx, receipt.Snapshot, run, ref, func(_ context.Context, login string, secret vault.PlainSecret) error {
		if string(secret) != expected[login] {
			t.Fatal("imported secret changed")
		}
		seen[login] = true
		return nil
	}, func(context.Context) error {
		auth, e := os.ReadFile(filepath.Join(installation, "auth.caddy"))
		if e != nil {
			return e
		}
		original, e := os.ReadFile(filepath.Join(receipt.Snapshot, "auth.caddy"))
		if !bytes.Equal(auth, original) {
			t.Fatal("handoff changed imported auth")
		}
		return e
	})
	reg.Close()
	if e != nil {
		t.Fatal("MIG05 storage finalization refused", e)
	}
	if !seen["Alice"] || !seen["master_user"] {
		t.Fatal("MIG05 did not check both exact logins")
	}
	db, e = sql.Open("sqlite3", dbPath)
	if e != nil {
		t.Fatal(e)
	}
	defer db.Close()
	for login, password := range expected {
		var uid, kind, status string
		var protected int
		var n, c []byte
		if e = db.QueryRow("SELECT u.id,u.kind,u.protected,u.status,c.nonce,c.ciphertext FROM users u JOIN user_current_credentials p ON p.user_id=u.id JOIN credentials c ON c.id=p.credential_id WHERE u.login=?", login).Scan(&uid, &kind, &protected, &status, &n, &c); e != nil {
			t.Fatal(e)
		}
		plain, e := cipher.Decrypt(vault.Binding{UserID: uid, SecretVersion: 1, KeyVersion: 1}, n, c)
		if e != nil || string(plain) != password {
			t.Fatal("registry password mismatch")
		}
		clear(plain)
		master := login == "master_user"
		if status != "active" || (kind == "service") != master || (protected == 1) != master {
			t.Fatal("registry identity/status mismatch")
		}
	}
	var owner string
	if e = db.QueryRow("SELECT password_hash FROM admin_accounts WHERE id='fresh-owner'").Scan(&owner); e != nil || owner != "fresh-owner-hash" {
		t.Fatal("destination owner changed")
	}
	afterKey, e := os.ReadFile(keyPath)
	if e != nil || !bytes.Equal(afterKey, key) {
		t.Fatal("destination key changed")
	}
	afterSource, e := os.ReadFile(input)
	if e != nil || sha256.Sum256(afterSource) != sourceHash {
		t.Fatal("source JSON changed")
	}
}
