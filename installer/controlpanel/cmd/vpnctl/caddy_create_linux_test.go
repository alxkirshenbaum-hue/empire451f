//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

type fileCaddyRuntime struct {
	path  string
	loads int
}

func (r *fileCaddyRuntime) Read(context.Context) ([]byte, error) { return os.ReadFile(r.path) }
func (r *fileCaddyRuntime) Validate(_ context.Context, b []byte) error {
	if !json.Valid(b) {
		return fmt.Errorf("invalid synthetic config")
	}
	return nil
}
func (r *fileCaddyRuntime) Load(_ context.Context, b []byte) error {
	r.loads++
	if err := os.WriteFile(r.path, b, 0600); err != nil {
		return err
	}
	if os.Getenv("VPN_CREATE_CRASH_AFTER_LOAD") == "1" {
		os.Exit(86)
	}
	return nil
}

func TestCaddyCreateCrashChild(t *testing.T) {
	root := os.Getenv("VPN_CREATE_CRASH_ROOT")
	if root == "" {
		t.Skip("crash child")
	}
	helper, err := filepath.Abs("../../../owned_auth.py")
	if err != nil {
		t.Fatal(err)
	}
	w := createCaddyWorker{state: filepath.Join(root, "state", "lab"), config: filepath.Join(root, "etc"), lock: filepath.Join(root, "lock"), panel: filepath.Join(root, "panel"), run: "a9b5c248-884a-40f0-823a-4dae9a541e3b", helper: helper, runtime: &fileCaddyRuntime{path: filepath.Join(root, "live.json")}, probe: func(context.Context, string, vault.PlainSecret) error { return nil }}
	if _, err = w.once(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("did not reach crash checkpoint")
}

func TestCaddyCreateFileSaga(t *testing.T) {
	for _, failure := range []string{"none", "after-load", "sqlite", "mixed-files", "post-commit-cleanup", "after-finish", "drift", "other-reconcile", "two-running"} {
		t.Run(failure, func(t *testing.T) {
			ctx := context.Background()
			root := t.TempDir()
			state := filepath.Join(root, "state", "lab")
			config := filepath.Join(root, "etc")
			panel := filepath.Join(root, "panel")
			base := filepath.Join(config, "lab")
			for _, p := range []string{state, base, panel} {
				if err := os.MkdirAll(p, 0700); err != nil {
					t.Fatal(err)
				}
			}
			put := func(path string, b []byte) {
				t.Helper()
				if err := os.WriteFile(path, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			run := "a9b5c248-884a-40f0-823a-4dae9a541e3b"
			auth := []byte("basic_auth \"canary\" \"unchanged\"\n")
			authPath := filepath.Join(base, "auth.caddy")
			put(authPath, auth)
			caddyfile := filepath.Join(base, "Caddyfile")
			put(caddyfile, []byte("synthetic unchanged Caddyfile"))
			meta := map[string]any{"config": map[string]string{"id": "lab"}, "files": map[string]string{caddyfile: fmt.Sprintf("%x", sha256.Sum256([]byte("synthetic unchanged Caddyfile")))}, "panel_run_id": run, "panel_generation": 1, "panel_auth_hash": fmt.Sprintf("%x", sha256.Sum256(auth))}
			manifest, _ := json.Marshal(meta)
			manifestPath := filepath.Join(state, "manifest.json")
			put(manifestPath, manifest)
			key := bytes.Repeat([]byte{19}, 32)
			put(filepath.Join(panel, "vault.key"), key)
			cipher, _ := vault.New(key)
			dbPath := filepath.Join(panel, "state.db")
			reg, err := storage.Open(ctx, dbPath, cipher, 1)
			if err != nil {
				t.Fatal(err)
			}
			reg.Close()
			db, err := sql.Open("sqlite3", dbPath)
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			execSQL := func(q string, args ...any) {
				t.Helper()
				if _, err := db.Exec(q, args...); err != nil {
					t.Fatal(err)
				}
			}
			execSQL("INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'verified_cutover','{}','now','verified_cutover')", run)
			execSQL("INSERT INTO profile_templates VALUES('t','sfa','SFA','naive_https',1)")
			execSQL("INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at) VALUES('r','t','1','sfa','1.14.4','{}','fixture','approved',CURRENT_TIMESTAMP)")
			lock := filepath.Join(root, "lock")
			receipt, err := queueFromInstallation(state, config, lock, panel, run, "New-User")
			if err != nil {
				t.Fatal(err)
			}
			double := base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte("canary:unchanged"))))
			live, _ := json.Marshal(map[string]any{"routes": []any{map[string]any{"handler": "forward_proxy", "auth_credentials": []string{double}, "upstream": "kept"}}, "site": "kept"})
			livePath := filepath.Join(root, "live.json")
			put(livePath, live)
			rt := &fileCaddyRuntime{path: livePath}
			helper, err := filepath.Abs("../../../owned_auth.py")
			if err != nil {
				t.Fatal(err)
			}
			probes := 0
			w := createCaddyWorker{state: state, config: config, lock: lock, panel: panel, run: run, helper: helper, runtime: rt, probe: func(_ context.Context, login string, secret vault.PlainSecret) error {
				probes++
				if login != "New-User" || len(secret) == 0 {
					t.Fatal("wrong probe credential")
				}
				return nil
			}}
			if failure != "none" && failure != "after-load" {
				execSQL("CREATE TRIGGER reject_finish BEFORE UPDATE OF status ON operations WHEN NEW.status='succeeded' BEGIN SELECT RAISE(ABORT,'fixture'); END")
			}
			if failure == "after-load" {
				child := exec.Command(os.Args[0], "-test.run=^TestCaddyCreateCrashChild$")
				child.Env = append(os.Environ(), "VPN_CREATE_CRASH_ROOT="+root, "VPN_CREATE_CRASH_AFTER_LOAD=1")
				var exited *exec.ExitError
				if err = child.Run(); !errors.As(err, &exited) || exited.ExitCode() != 86 {
					t.Fatal("child failed before checkpoint", err)
				}
			}
			got, err := w.once()
			if failure == "none" || failure == "after-load" {
				if err != nil || got != receipt {
					t.Fatal("create failed", err)
				}
			} else {
				if err == nil {
					t.Fatal("expected failed SQLite commit")
				}
				execSQL("DROP TRIGGER reject_finish")
				if failure == "mixed-files" {
					put(manifestPath, manifest)
				}
				if failure == "post-commit-cleanup" || failure == "after-finish" {
					reg, e := storage.Open(ctx, dbPath, cipher, 1)
					if e != nil {
						t.Fatal(e)
					}
					if e = reg.CompleteVerifiedCreate(ctx, receipt, 1); e != nil {
						t.Fatal(e)
					}
					reg.Close()
					if failure == "after-finish" {
						if err = os.Remove(filepath.Join(state, "panel-auth-pending.json")); err != nil {
							t.Fatal(err)
						}
					}
				}
				if failure == "drift" {
					put(authPath, []byte("external change"))
				}
				if failure == "other-reconcile" || failure == "two-running" {
					reg, e := storage.Open(ctx, dbPath, cipher, 1)
					if e != nil {
						t.Fatal(e)
					}
					other, e := reg.QueueCreate(ctx, "owner", "ee5903c0-bbd4-4eb2-aa4f-8a489c4884cf", storage.CreateRequest{Login: "Other", DisplayName: "Other", TemplateRevisionID: "r", TargetClient: "sfa"})
					if e != nil {
						t.Fatal(e)
					}
					if e = reg.Transition(ctx, other.OperationID, "queued", "running"); e != nil {
						t.Fatal(e)
					}
					if failure == "other-reconcile" {
						if e = reg.Transition(ctx, other.OperationID, "running", "reconcile_required"); e != nil {
							t.Fatal(e)
						}
					}
					reg.Close()
				}
				got, err = w.once()
				if failure == "other-reconcile" || failure == "two-running" {
					if !errors.Is(err, storage.ErrJournalConflict) {
						t.Fatal("ignored other uncertain operation", err)
					}
					return
				}
				if failure == "drift" {
					if err == nil {
						t.Fatal("overwrote drift")
					}
					after, _ := os.ReadFile(authPath)
					if string(after) != "external change" {
						t.Fatal("lost external change")
					}
					return
				}
				if err != nil || got != receipt {
					t.Fatal("recovery failed", err)
				}
			}
			wantLoads := 1
			if failure == "after-load" {
				wantLoads = 0
			}
			if rt.loads != wantLoads {
				t.Fatal("recovery reloaded live config")
			}
			if probes < 1 {
				t.Fatal("did not verify")
			}
			if _, err = os.Stat(filepath.Join(state, "panel-auth-pending.json")); !os.IsNotExist(err) {
				t.Fatal("pending journal remains")
			}
			if _, err = os.Stat(w.directory(receipt.OperationID)); !os.IsNotExist(err) {
				t.Fatal("plaintext prepared snapshot remains")
			}
			if generation, err := verifyOwnedFiles(state, config, run); err != nil || generation != 2 {
				t.Fatal("inconsistent committed files", err)
			}
			var op, user string
			if err = db.QueryRow("SELECT o.status,u.status FROM operations o JOIN users u ON u.id=o.target_id WHERE o.id=?", receipt.OperationID).Scan(&op, &user); err != nil || op != "succeeded" || user != "active" {
				t.Fatal("not activated", err)
			}
			if again, err := w.once(); err != nil || again.OperationID != "" {
				t.Fatal("duplicate execution", err)
			}
		})
	}
}
