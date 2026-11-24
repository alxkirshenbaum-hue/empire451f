//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"os"
	"path/filepath"
	"testing"
)

func TestMaintenanceWorkerRealArtifact(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root fixture policy")
	}
	root := t.TempDir()
	if e := os.Chmod(root, 0700); e != nil {
		t.Fatal(e)
	}
	state := filepath.Join(root, "state", "lab")
	config := filepath.Join(root, "etc")
	panel := filepath.Join(root, "panel")
	dest := filepath.Join(root, "captures")
	for _, p := range []string{state, filepath.Join(config, "lab"), panel, dest} {
		if err := os.MkdirAll(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	put := func(p string, b []byte) {
		t.Helper()
		if err := os.WriteFile(p, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	hash := func(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }
	run := "a9b5c248-884a-40f0-823a-4dae9a541e3b"
	auth := filepath.Join(config, "lab", "auth.caddy")
	managed := filepath.Join(config, "lab", "Caddyfile")
	put(auth, []byte("basic_auth \"master_user\" \"fixture-master\"\n"))
	put(managed, []byte("fixture managed"))
	meta := map[string]any{"config": map[string]string{"id": "lab"}, "files": map[string]string{managed: hash([]byte("fixture managed"))}, "panel_run_id": run, "panel_generation": 1, "panel_auth_hash": hash([]byte("basic_auth \"master_user\" \"fixture-master\"\n"))}
	raw, _ := json.Marshal(meta)
	put(filepath.Join(state, "manifest.json"), raw)
	key := bytes.Repeat([]byte{19}, 32)
	put(filepath.Join(panel, "vault.key"), key)
	cipher, _ := vault.New(key)
	reg, err := storage.Open(context.Background(), filepath.Join(panel, "state.db"), cipher, 1)
	if err != nil {
		t.Fatal(err)
	}
	reg.Close()
	db, err := sql.Open("sqlite3", filepath.Join(panel, "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'verified_cutover','{}','now','verified_cutover')", run)
	nonce, encrypted, err := cipher.Encrypt(vault.Binding{UserID: "master", SecretVersion: 1, KeyVersion: 1}, vault.PlainSecret("fixture-master"))
	if err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO users(id,login,display_name,kind,protected,source,status,created_at,updated_at) VALUES('master','master_user','master_user','service',1,'legacy_import','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
	exec("INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) VALUES('credential','master',1,?,?,?,1,CURRENT_TIMESTAMP)", vault.Algorithm, nonce, encrypted)
	exec("INSERT INTO user_current_credentials VALUES('master','credential',CURRENT_TIMESTAMP)")

	put(filepath.Join(state, "clients.json"), []byte("synthetic clients"))
	put(filepath.Join(state, "vpn-fixture.json"), []byte("synthetic profile"))
	helper, e := filepath.Abs("../../../backup_artifact.py")
	if e != nil {
		t.Fatal(e)
	}
	helperBytes, e := os.ReadFile(helper)
	if e != nil {
		t.Fatal(e)
	}
	helper = filepath.Join(root, "backup_artifact.py")
	put(helper, helperBytes)
	recipient := filepath.Join(root, "recipient.pem")
	private := filepath.Join(root, "owner-private.pem")
	rsaKey, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	publicDER, e := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	put(recipient, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	put(private, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	rec, e := artifactCommand(context.Background(), helper, map[string]string{"action": "recipient", "public_key_path": recipient})
	if e != nil {
		t.Fatal(e)
	}
	policy := workerPolicy{BackupHelper: helper, BackupRecipient: recipient, BackupDirectory: dest, BackupWork: filepath.Join(root, "private-work")}
	if e = os.Mkdir(policy.BackupWork, 0700); e != nil {
		t.Fatal(e)
	}
	w := createCaddyWorker{state: state, config: config, panel: panel, run: run, backupPolicy: &policy}
	lock := filepath.Join(root, "lock")
	apply := func(action string, bid, sha string) (storage.MaintenanceJob, error) {
		var job storage.MaintenanceJob
		_, e := withOwnedInstallation(state, config, lock, panel, run, func(ctx context.Context, r *storage.Registry) (storage.Receipt, error) {
			if e := r.ConfigureBackups(ctx, rec.KeyFingerprint); e != nil {
				return storage.Receipt{}, e
			}
			var e error
			job, e = r.QueueMaintenance(ctx, run, "owner", fmt.Sprintf("fixture-%s-%s", action, bid), storage.MaintenanceRequest{Action: action, BackupID: bid, ExpectedHash: sha})
			if e != nil {
				return storage.Receipt{}, e
			}
			return w.applyMaintenance(ctx, r, job)
		})
		return job, e
	}
	created, e := apply("backup.create", "", "")
	if e != nil {
		t.Fatal(e)
	}
	reg, e = storage.Open(context.Background(), filepath.Join(panel, "state.db"), cipher, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer reg.Close()
	backup, e := reg.GetBackupInternal(context.Background(), created.BackupID)
	if e != nil || backup.Status != "created" || backup.VerifiedAt != "" {
		t.Fatal(backup, e)
	}
	ciphertextBytes, e := os.ReadFile(backup.EncryptedPath)
	if e != nil || fmt.Sprintf("%x", sha256.Sum256(ciphertextBytes)) != backup.SHA256 {
		t.Fatal("cipher digest", e)
	}
	if bytes.Contains(ciphertextBytes, []byte("fixture-master")) {
		t.Fatal("plaintext in ciphertext")
	}
	decrypted := filepath.Join(root, "owner-decrypted.tar")
	if _, e = artifactCommand(context.Background(), helper, map[string]string{"action": "decrypt", "envelope": backup.EncryptedPath, "private_key_path": private, "output": decrypted, "expected_sha256": backup.SHA256}); e != nil {
		t.Fatal("owner decrypt", e)
	}
	prepareParent := filepath.Join(root, "restore-candidates")
	if e = os.Mkdir(prepareParent, 0700); e != nil {
		t.Fatal(e)
	}
	sourceBefore, e := os.ReadFile(backup.EncryptedPath)
	if e != nil {
		t.Fatal(e)
	}
	var cliOut, cliErr bytes.Buffer
	if code := execute([]string{"backup", "offline-verify", "--envelope", backup.EncryptedPath, "--private-key", private, "--cipher-sha256", backup.SHA256, "--manifest-sha256", backup.ManifestSHA256, "--owner-run", run, "--own-operation", created.OperationID, "--backup-id", created.BackupID, "--helper", helper, "--source-panel-root", panel, "--source-state-root", state, "--source-config-root", config, "--staging", filepath.Join(root, "offline-checked"), "--prepare-parent", prepareParent}, &cliOut, &cliErr); code != 0 {
		t.Fatalf("offline prepare code%d: %s", code, cliErr.String())
	}
	var prepared struct {
		Path string `json:"prepared_copy"`
	}
	if e = json.Unmarshal(cliOut.Bytes(), &prepared); e != nil || prepared.Path == "" {
		t.Fatal("prepared receipt", e)
	}
	if _, e = storage.InspectCapturedSnapshot(context.Background(), prepared.Path, cipher, run, ""); e != nil {
		t.Fatal("prepared canonical", e)
	}
	sourceAfter, e := os.ReadFile(backup.EncryptedPath)
	if e != nil || !bytes.Equal(sourceBefore, sourceAfter) {
		t.Fatal("source ciphertext changed", e)
	}
	entries, e := os.ReadDir(policy.BackupWork)
	if e != nil || len(entries) != 0 {
		t.Fatal("plaintext work leaked", e)
	}
	waiting, e := apply("backup.verify", created.BackupID, backup.SHA256)
	if e != nil {
		t.Fatal(e)
	}
	next, e := reg.NextMaintenance(context.Background(), run)
	if e != nil || next.Phase != "verifying" {
		t.Fatal(next, e)
	}
	// A second common-writer callback acquires the lock while attestation waits.
	if _, e = withOwnedInstallation(state, config, lock, panel, run, func(ctx context.Context, r *storage.Registry) (storage.Receipt, error) {
		return w.applyMaintenance(ctx, r, next)
	}); e != nil {
		t.Fatal("waiting retained writer lock", e)
	}
	if e = reg.CancelMaintenance(context.Background(), "owner", waiting.OperationID); e != nil {
		t.Fatal(e)
	}
	// Existing cipher output must survive O_EXCL failure unchanged and require reconciliation.
	var collision storage.MaintenanceJob
	_, e = withOwnedInstallation(state, config, lock, panel, run, func(ctx context.Context, r *storage.Registry) (storage.Receipt, error) {
		var e error
		collision, e = r.QueueMaintenance(ctx, run, "owner", "collision", storage.MaintenanceRequest{Action: "backup.create"})
		if e != nil {
			return storage.Receipt{}, e
		}
		put(filepath.Join(dest, collision.BackupID+".jwe"), []byte("existing ciphertext sentinel"))
		return w.applyMaintenance(ctx, r, collision)
	})
	if e == nil {
		t.Fatal("existing cipher overwritten")
	}
	old, e := os.ReadFile(filepath.Join(dest, collision.BackupID+".jwe"))
	if e != nil || string(old) != "existing ciphertext sentinel" {
		t.Fatal("existing cipher changed", e)
	}
	next, e = reg.NextMaintenance(context.Background(), run)
	if e != nil || next.Phase != "reconcile_required" {
		t.Fatal(next, e)
	}
	entries, e = os.ReadDir(policy.BackupWork)
	if e != nil || len(entries) != 0 {
		t.Fatal("failed work leaked", e)
	}
}
