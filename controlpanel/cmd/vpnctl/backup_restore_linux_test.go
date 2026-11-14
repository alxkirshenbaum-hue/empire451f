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
	"io"
	"os"
	"path/filepath"
	"testing"
)

func restoreArchiveFixture(t *testing.T) (ManagedArchive, string, string) {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
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

	return archive, root, run
}

func TestManagedArchiveVerify(t *testing.T) {
	archive, root, run := restoreArchiveFixture(t)
	stage := filepath.Join(root, "restored")
	out, err := verifyManagedArchive(context.Background(), archive.Path, stage, archive.ManifestSHA256, run, "", RestoreSourceRoots{PanelRoot: filepath.Join(root, "panel"), StateRoot: filepath.Join(root, "state", "lab"), ConfigRoot: filepath.Join(root, "etc")})
	if err != nil {
		t.Fatal(err)
	}
	if out.Inspection.Users != 1 || out.Inspection.SchemaVersion != 8 || out.Root != stage {
		t.Fatal("inspection mismatch")
	}
	for _, m := range out.Manifest.Members {
		p := filepath.Join(stage, m.Path[1:])
		raw, err := os.ReadFile(p)
		if err != nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != m.SHA256 {
			t.Fatal("mapped member differs")
		}
	}
	if _, err = verifyManagedArchive(context.Background(), archive.Path, stage, archive.ManifestSHA256, run, "", RestoreSourceRoots{PanelRoot: filepath.Join(root, "panel"), StateRoot: filepath.Join(root, "state", "lab"), ConfigRoot: filepath.Join(root, "etc")}); err == nil {
		t.Fatal("occupied staging overwritten")
	}
}

func rewriteRestoreArchive(t *testing.T, archive ManagedArchive, mutate func(*tar.Header, []byte) (*tar.Header, []byte), extra bool) string {
	t.Helper()
	raw, err := os.ReadFile(archive.Path)
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(bytes.NewReader(raw))
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			t.Fatal(e)
		}
		body, _ := io.ReadAll(tr)
		h, body = mutate(h, body)
		h.Size = int64(len(body))
		if e = tw.WriteHeader(h); e != nil {
			t.Fatal(e)
		}
		tw.Write(body)
	}
	if extra {
		tw.WriteHeader(&tar.Header{Name: "../escape", Mode: 0600, Size: 1, Typeflag: tar.TypeReg, Format: tar.FormatUSTAR})
		tw.Write([]byte("x"))
	}
	if err = tw.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(filepath.Dir(archive.Path), "modified.tar")
	if err = os.WriteFile(path, buf.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestManagedArchiveVerifyRejects(t *testing.T) {
	for _, scenario := range []string{"tamper", "wrong-owner", "wrong-manifest", "extra", "link", "pax", "duplicate", "cancel", "vault", "schema", "reconcile", "wrong-roots", "overlapping-roots"} {
		t.Run(scenario, func(t *testing.T) {
			archive, root, run := restoreArchiveFixture(t)
			stage := filepath.Join(root, "rejected")
			path := archive.Path
			expected := archive.ManifestSHA256
			ctx := context.Background()
			switch scenario {
			case "wrong-roots", "overlapping-roots":
			case "wrong-owner":
				run = "wrong"
			case "wrong-manifest":
				expected = fmt.Sprintf("%064d", 0)
			case "cancel":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			default:
				var original ManagedArchiveManifest
				ar, _ := os.Open(archive.Path)
				reader := tar.NewReader(ar)
				payloads := map[string][]byte{}
				for {
					h, e := reader.Next()
					if e == io.EOF {
						break
					}
					if e != nil {
						t.Fatal(e)
					}
					body, _ := io.ReadAll(reader)
					if h.Name == "manifest.json" {
						json.Unmarshal(body, &original)
					} else {
						payloads[h.Name] = body
					}
				}
				ar.Close()
				changedBlob := ""
				var replacement []byte
				if scenario == "vault" || scenario == "schema" || scenario == "reconcile" {
					target := original.RegistryPath
					if scenario == "vault" {
						target = filepath.Join(filepath.Dir(target), "vault.key")
					}
					for _, m := range original.Members {
						if m.Path == target {
							changedBlob = m.Blob
						}
					}
					if scenario == "vault" {
						replacement = bytes.Repeat([]byte{22}, 32)
					} else {
						dbpath := filepath.Join(root, "tampered.db")
						os.WriteFile(dbpath, payloads[changedBlob], 0600)
						db, e := sql.Open("sqlite3", dbpath)
						if e != nil {
							t.Fatal(e)
						}
						query := "UPDATE schema_migrations SET sha256='incorrect' WHERE version=1"
						if scenario == "reconcile" {
							query = "INSERT INTO operations(id,actor_id,kind,status,idempotency_key,request_hash,correlation_id,created_at) VALUES('stray','fixture','backup.create','reconcile_required','stray','hash','stray','now')"
						}
						if _, e = db.Exec(query); e != nil {
							t.Fatal(e)
						}
						db.Close()
						replacement, _ = os.ReadFile(dbpath)
					}
				}
				index := 0
				path = rewriteRestoreArchive(t, archive, func(h *tar.Header, b []byte) (*tar.Header, []byte) {
					if h.Name != "manifest.json" {
						switch scenario {
						case "tamper":
							if len(b) > 0 {
								b[0] ^= 1
							}
						case "link":
							h.Typeflag = tar.TypeSymlink
							h.Linkname = "/etc/passwd"
							b = nil
						case "pax":
							h.Format = tar.FormatPAX
							h.PAXRecords = map[string]string{"comment": "unsupported"}
						case "duplicate":
							h.Name = "blobs/0000"
						}
					}
					if h.Name == changedBlob {
						b = replacement
					}
					if h.Name == "manifest.json" && changedBlob != "" {
						var m ManagedArchiveManifest
						json.Unmarshal(b, &m)
						hash := fmt.Sprintf("%x", sha256.Sum256(replacement))
						for i := range m.Members {
							if m.Members[i].Blob == changedBlob {
								m.Members[i].SHA256 = hash
								m.Members[i].Size = int64(len(replacement))
								if _, ok := m.Observations[m.Members[i].Path]; ok {
									m.Observations[m.Members[i].Path] = hash
								}
							}
						}
						if scenario != "vault" {
							m.Capture.SHA256 = hash
							m.Capture.Bytes = int64(len(replacement))
						}
						b, _ = json.Marshal(m)
						expected = fmt.Sprintf("%x", sha256.Sum256(b))
					}
					index++
					return h, b
				}, scenario == "extra")
			}
			roots := RestoreSourceRoots{PanelRoot: filepath.Join(root, "panel"), StateRoot: filepath.Join(root, "state", "lab"), ConfigRoot: filepath.Join(root, "etc")}
			if scenario == "wrong-roots" {
				roots.PanelRoot = filepath.Join(root, "other")
			}
			if scenario == "overlapping-roots" {
				roots.ConfigRoot = root
			}
			if _, err := verifyManagedArchive(ctx, path, stage, expected, run, "", roots); err == nil {
				t.Fatal("unsafe archive accepted")
			}
			if _, err := os.Lstat(stage); !os.IsNotExist(err) {
				t.Fatal("failed verification leaked staging")
			}
		})
	}
}
