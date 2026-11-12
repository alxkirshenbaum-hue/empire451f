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

func TestStagePythonPlan(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "state.db")
	key := bytes.Repeat([]byte{21}, 32)
	cipher, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	reg, err := storage.Open(context.Background(), dbPath, cipher, 1)
	if err != nil {
		t.Fatal(err)
	}
	reg.Close()
	keyFile := filepath.Join(dir, "key")
	if err = os.WriteFile(keyFile, key, 0600); err != nil {
		t.Fatal(err)
	}
	snap := filepath.Join(dir, "snapshot")
	if err = os.Mkdir(snap, 0700); err != nil {
		t.Fatal(err)
	}
	password := "synthetic mixed Case password"
	names := []string{"Legacy.Name", "master_user"}
	raw := []byte(fmt.Sprintf("basic_auth %q %q\nbasic_auth %q %q\n", names[0], password, names[1], password))
	if err = os.WriteFile(filepath.Join(snap, "auth.caddy"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	put := func(name string, value any) {
		t.Helper()
		b, e := json.Marshal(value)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(filepath.Join(snap, name), b, 0600); e != nil {
			t.Fatal(e)
		}
	}
	hash := sha256.Sum256(raw)
	put("manifest.json", map[string]any{"config": map[string]string{"id": "nh1", "domain": "test.invalid"}, "files": map[string]string{"/etc/empire-vpn/nh1/auth.caddy": fmt.Sprintf("%x", hash)}})
	clients := []map[string]string{}
	for _, name := range names {
		clients = append(clients, map[string]string{"username": name, "password": password})
	}
	put("clients.json", map[string]any{"format": "empire-vpn-clients", "schema_version": 1, "clients": clients})
	put("master_user.sfa.json", map[string]any{"outbounds": []map[string]string{{"type": "naive", "server": "test.invalid", "username": "master_user", "password": password}}})
	inspect := func(args ...string) map[string]any {
		t.Helper()
		base := []string{"-B", "../../../inspect_legacy.py", snap, "--registry", dbPath}
		output, e := exec.Command("python3", append(base, args...)...).Output()
		if e != nil {
			t.Fatal(e)
		}
		var obj map[string]any
		if e = json.Unmarshal(output, &obj); e != nil {
			t.Fatal(e)
		}
		return obj
	}
	run := inspect()["run_id"].(string)
	inspect("--plan", run)
	stage := func(id string, want int, extra ...string) []byte {
		t.Helper()
		var stdout, stderr bytes.Buffer
		got := execute(append([]string{"migration", "execute", "--approved-plan", id, "--staging-db", dbPath, "--snapshot", snap, "--vault-key-file", keyFile}, extra...), &stdout, &stderr)
		if got != want {
			if got == 3 {
				probe, openErr := storage.Open(context.Background(), dbPath, cipher, 1)
				if openErr != nil {
					t.Fatalf("reopen synthetic registry: %v", openErr)
				}
				probe.Close()
			}
			t.Fatalf("exit %d, expected %d: %s", got, want, stderr.String())
		}
		if bytes.Contains(stdout.Bytes(), []byte(password)) || bytes.Contains(stderr.Bytes(), []byte(password)) {
			t.Fatal("credential in output")
		}
		return stdout.Bytes()
	}
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	checkCount := func(table string, want int) {
		t.Helper()
		var n int
		if e := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); e != nil || n != want {
			t.Fatalf("%s count=%d err=%v", table, n, e)
		}
	}
	if e := os.WriteFile(filepath.Join(snap, "auth.caddy"), append(raw, '\n'), 0600); e != nil {
		t.Fatal(e)
	}
	if !bytes.Contains(stage(run, 4, "--json"), []byte(`"code":"CONFIG_DRIFT"`)) {
		t.Fatal("missing drift code")
	}
	checkCount("users", 0)
	if e := os.WriteFile(filepath.Join(snap, "auth.caddy"), raw, 0600); e != nil {
		t.Fatal(e)
	}
	stage(run, 4)
	run = inspect()["run_id"].(string)
	inspect("--plan", run)
	if _, err = db.Exec("CREATE TRIGGER injected_failure BEFORE INSERT ON users WHEN NEW.login='master_user' BEGIN SELECT RAISE(ABORT,'injected'); END;"); err != nil {
		t.Fatal(err)
	}
	stage(run, 9)
	for _, table := range []string{"users", "user_current_credentials", "credentials", "operations", "legacy_migration_items"} {
		checkCount(table, 0)
	}
	if _, err = db.Exec("DROP TRIGGER injected_failure"); err != nil {
		t.Fatal(err)
	}
	first := stage(run, 0)
	if !bytes.Equal(first, stage(run, 0, "--json")) || len(stage(run, 0, "--quiet")) != 0 {
		t.Fatal("output mode contract")
	}
	if !bytes.Equal(first, stage(run, 0)) {
		t.Fatal("receipt changed on replay")
	}
	checkCount("operations", 1)
	checkCount("users", 2)
	for _, name := range names {
		var uid, kind, finding string
		var protected bool
		var nonce, sealed []byte
		err = db.QueryRow(`SELECT u.id,u.kind,u.protected,c.nonce,c.ciphertext,m.finding_code FROM users u
 JOIN user_current_credentials a ON a.user_id=u.id JOIN credentials c ON c.id=a.credential_id
 JOIN legacy_migration_items m ON m.imported_user_id=u.id WHERE u.login=?`, name).Scan(&uid, &kind, &protected, &nonce, &sealed, &finding)
		if err != nil {
			t.Fatal(err)
		}
		master := name == "master_user"
		if protected != master || (kind == "service") != master || (finding == "legacy_accepted") == master {
			t.Fatal("incorrect legacy identity")
		}
		plain, e := cipher.Decrypt(vault.Binding{UserID: uid, SecretVersion: 1, KeyVersion: 1}, nonce, sealed)
		if e != nil || string(plain) != password {
			t.Fatal("credential roundtrip failed")
		}
		clear(plain)
	}
}
