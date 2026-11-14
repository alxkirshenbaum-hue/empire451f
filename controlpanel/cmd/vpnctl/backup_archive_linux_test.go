//go:build linux

package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestManagedArchiveRoundtrip(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	source := filepath.Join(root, "source")
	payload := []byte("synthetic secret")
	if err := os.WriteFile(source, payload, 0640); err != nil {
		t.Fatal(err)
	}
	hash := fmt.Sprintf("%x", sha256.Sum256(payload))
	out, err := writeManagedArchive(context.Background(), root, map[string]string{source: hash}, ManagedArchiveManifest{Format: "vpn-control-managed-backup-v1", OwnerRun: "fixture", Generation: 7})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(out.Path)
	if err != nil {
		t.Fatal(err)
	}
	if out.SHA256 != fmt.Sprintf("%x", sha256.Sum256(raw)) || out.Bytes != int64(len(raw)) {
		t.Fatal("archive digest/size mismatch")
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	hdr, err := tr.Next()
	if err != nil || hdr.Name != "blobs/0000" {
		t.Fatalf("blob: %v %v", hdr, err)
	}
	body, _ := io.ReadAll(tr)
	if !bytes.Equal(body, payload) {
		t.Fatal("payload differs")
	}
	hdr, err = tr.Next()
	if err != nil || hdr.Name != "manifest.json" {
		t.Fatal("manifest absent")
	}
	body, _ = io.ReadAll(tr)
	var manifest ManagedArchiveManifest
	if json.Unmarshal(body, &manifest) != nil || len(manifest.Members) != 1 {
		t.Fatal("invalid manifest")
	}
	m := manifest.Members[0]
	if m.Path != source || m.SHA256 != hash || m.Mode != 0640 || m.Size != int64(len(payload)) || len(m.Xattrs) != 0 {
		t.Fatalf("metadata mismatch: %+v", m)
	}
	if out.ManifestSHA256 != fmt.Sprintf("%x", sha256.Sum256(body)) {
		t.Fatal("manifest digest differs")
	}
	if _, err = tr.Next(); err != io.EOF {
		t.Fatal("extra members")
	}
	info, _ := os.Stat(out.Path)
	parent, _ := os.Stat(filepath.Dir(out.Path))
	if info.Mode().Perm() != 0600 || parent.Mode().Perm() != 0700 {
		t.Fatal("staging not private")
	}
}

func TestManagedArchiveRejectsAndCleans(t *testing.T) {
	for _, scenario := range []string{"hash", "symlink", "hardlink", "oversize", "xattr", "cancel", "relative"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			os.Chmod(root, 0700)
			source := filepath.Join(root, "source")
			os.WriteFile(source, []byte("fixture"), 0600)
			hash := fmt.Sprintf("%x", sha256.Sum256([]byte("fixture")))
			ctx := context.Background()
			switch scenario {
			case "hash":
				hash = fmt.Sprintf("%064d", 0)
			case "symlink":
				os.Rename(source, source+"-real")
				os.Symlink(source+"-real", source)
			case "hardlink":
				os.Link(source, source+"-link")
			case "oversize":
				f, _ := os.OpenFile(source, os.O_WRONLY, 0)
				f.Truncate(32 * 1024 * 1024)
				f.Close()
			case "xattr":
				if err := unix.Setxattr(source, "user.fixture", []byte("value"), 0); err != nil {
					t.Skip("filesystem does not support user xattrs")
				}
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "relative":
				source = "relative"
			}
			out, err := writeManagedArchive(ctx, root, map[string]string{source: hash}, ManagedArchiveManifest{})
			if err == nil || out.Path != "" {
				t.Fatal("unsafe input accepted")
			}
			matches, _ := filepath.Glob(filepath.Join(root, "managed-archive-*"))
			if len(matches) != 0 {
				t.Fatal("plaintext staging leaked")
			}
		})
	}
}

func TestManagedArchiveInstallationBinding(t *testing.T) {
	root := t.TempDir()
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
	put(auth, []byte("fixture auth"))
	put(managed, []byte("fixture managed"))
	meta := map[string]any{"config": map[string]string{"id": "lab"}, "files": map[string]string{managed: hash([]byte("fixture managed"))}, "panel_run_id": run, "panel_generation": 1, "panel_auth_hash": hash([]byte("fixture auth"))}
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
	var archive ManagedArchive
	_, err = withOwnedInstallation(state, config, filepath.Join(root, "lock"), panel, run, func(ctx context.Context, reg *storage.Registry) (storage.Receipt, error) {
		var e error
		archive, e = createInstallationArchive(ctx, reg, state, config, panel, run, dest, "")
		return storage.Receipt{}, e
	})
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(archive.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	tr := tar.NewReader(f)
	var manifest ManagedArchiveManifest
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		if h.Name == "manifest.json" {
			if e = json.NewDecoder(tr).Decode(&manifest); e != nil {
				t.Fatal(e)
			}
		}
	}
	if manifest.Capture.Inspection.SchemaVersion != 8 || manifest.Capture.Inspection.Users != 1 || manifest.Generation != 1 || manifest.OwnerRun != run {
		t.Fatal("archive binding missing")
	}
	seen := map[string]bool{}
	for _, m := range manifest.Members {
		seen[m.Path] = true
	}
	for _, p := range []string{filepath.Join(panel, "state.db"), filepath.Join(panel, "vault.key"), filepath.Join(state, "manifest.json"), auth, managed, filepath.Join(state, "clients.json"), filepath.Join(state, "vpn-fixture.json")} {
		if !seen[p] {
			t.Fatalf("missing member %s", p)
		}
	}
	entries, err := os.ReadDir(dest)
	if err != nil || len(entries) != 1 {
		t.Fatalf("capture staging leaked: %v %v", entries, err)
	}
}
