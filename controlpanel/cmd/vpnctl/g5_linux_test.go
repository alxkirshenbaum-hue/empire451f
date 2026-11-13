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
	"syscall"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func g5Fixture(t *testing.T, action string) (string, *createCaddyWorker, *sql.DB, storage.Receipt) {
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
	t.Cleanup(func() { _ = db.Close() })
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
	w.mutationProbe = func(context.Context, storage.AuthJob, vault.PlainSecret, vault.PlainSecret) error { return nil }
	if action != "create" {
		if _, err = w.once(); err != nil {
			t.Fatal(err)
		}
		queue := func(action string, version int64) storage.Receipt {
			rec, e := withOwnedInstallation(state, config, lock, panel, run, func(ctx context.Context, r *storage.Registry) (storage.Receipt, error) {
				return r.QueueOwnedMutation(ctx, run, "ssh-root", action+fmt.Sprint(version), storage.MutationRequest{UserID: receipt.UserID, Action: action, ExpectedVersion: version, Reason: "crash test", ConfirmDelete: true})
			})
			if e != nil {
				t.Fatal(e)
			}
			return rec
		}
		version := int64(2)
		if action == "enable" {
			queue("disable", version)
			if _, err = w.once(); err != nil {
				t.Fatal(err)
			}
			version++
		}
		receipt = queue(action, version)
	}
	return root, &w, db, receipt
}

func TestG5CrashChild(t *testing.T) {
	root := os.Getenv("VPN_G5_ROOT")
	if root == "" {
		t.Skip("isolated crash child")
	}
	target := os.Getenv("VPN_G5_POINT")
	ctx := context.Background()
	helper, err := filepath.Abs("../../../owned_auth.py")
	if err != nil {
		t.Fatal(err)
	}
	rt := &fileCaddyRuntime{path: filepath.Join(root, "live.json")}
	probeErr := func() error {
		if target == "after_reconcile_required" {
			return errors.New("synthetic probe failure")
		}
		return nil
	}
	w := createCaddyWorker{state: filepath.Join(root, "state", "lab"), config: filepath.Join(root, "etc"), lock: filepath.Join(root, "lock"), panel: filepath.Join(root, "panel"), run: "a9b5c248-884a-40f0-823a-4dae9a541e3b", helper: helper, runtime: rt,
		probe:         func(context.Context, string, vault.PlainSecret) error { return probeErr() },
		mutationProbe: func(context.Context, storage.AuthJob, vault.PlainSecret, vault.PlainSecret) error { return probeErr() },
	}
	w.checkpoint = func(point string) {
		if target == "after_rollback_verify" && point == "after_apply" {
			// Explicit SSH recovery branch on the same Prepared and file journal.
			// Preserve the old DB state; a crash here must block a blind reapply.
			data, e := os.ReadFile(filepath.Join(w.state, "panel-auth-pending.json"))
			if e != nil {
				t.Fatal(e)
			}
			var intent struct {
				Operation  string
				Generation int64
			}
			if json.Unmarshal(data, &intent) != nil {
				t.Fatal("intent")
			}
			p, e := caddy.ReadPrepared(w.directory(intent.Operation), intent.Operation, intent.Generation)
			if e != nil {
				t.Fatal(e)
			}
			defer p.Clear()
			if e = p.Rollback(ctx, rt, func(context.Context) error { return nil }); e != nil {
				t.Fatal(e)
			}
			rec := storage.Receipt{OperationID: intent.Operation}
			if e = w.files(ctx, "publish_files", rec, intent.Generation, map[string]any{"rollback": true}); e != nil {
				t.Fatal(e)
			}
			point = "after_rollback_verify"
		}
		if point == target {
			_ = syscall.Kill(os.Getpid(), syscall.SIGKILL)
			select {}
		}
	}
	if _, err = w.once(); err != nil {
		t.Fatal(err)
	}
	t.Fatal("named crash point not reached")
}

func TestG5NamedCrashMatrix(t *testing.T) {
	for _, action := range []string{"create", "disable", "enable", "rotate", "delete"} {
		for _, point := range caddy.G5FailurePoints {
			t.Run(action+"/"+point, func(t *testing.T) {
				root, w, db, rec := g5Fixture(t, action)
				before, e := w.runtime.Read(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				cipher, _ := vault.New(bytes.Repeat([]byte{19}, 32))
				registry, e := storage.Open(context.Background(), filepath.Join(root, "panel", "state.db"), cipher, 1)
				if e != nil {
					t.Fatal(e)
				}
				var expected []byte
				if action == "create" {
					secret, err := registry.OpenForPurpose(context.Background(), rec.UserID, storage.PrepareAuth)
					if err != nil {
						t.Fatal(err)
					}
					expected, e = caddy.PatchCreate(before, "New-User", string(secret))
					clear(secret)
				} else {
					job, err := registry.OwnedAuthJob(context.Background(), w.run, rec.OperationID)
					if err != nil {
						t.Fatal(err)
					}
					e = registry.WithMutationSecrets(context.Background(), job, func(login string, old, fresh vault.PlainSecret) error {
						var err error
						expected, err = caddy.PatchAuth(before, mutationChange(job, login, old, fresh))
						return err
					})
				}
				registry.Close()
				if e != nil {
					t.Fatal(e)
				}
				defer clear(expected)
				child := exec.Command(os.Args[0], "-test.run=^TestG5CrashChild$")
				child.Env = append(os.Environ(), "VPN_G5_ROOT="+root, "VPN_G5_POINT="+point)
				var exited *exec.ExitError
				e = child.Run()
				if !errors.As(e, &exited) {
					t.Fatal("child did not crash", e)
				}
				wait, ok := exited.Sys().(syscall.WaitStatus)
				if !ok || !wait.Signaled() || wait.Signal() != syscall.SIGKILL {
					t.Fatal("failed before named SIGKILL", point, e)
				}
				// Restart the canonical worker. It may complete proven candidate or block.
				_, _ = w.once()
				var phase, state string
				if e = db.QueryRow("SELECT o.status,u.status FROM operations o JOIN users u ON u.id=o.target_id WHERE o.id=?", rec.OperationID).Scan(&phase, &state); e != nil {
					t.Fatal(e)
				}
				live, e := w.runtime.Read(context.Background())
				if e != nil {
					t.Fatal(e)
				}
				if phase == "succeeded" {
					if !caddy.ConfigEqual(live, expected) {
						t.Fatal("succeeded without exact candidate")
					}
					if _, e = verifyOwnedFiles(w.state, w.config, w.run); e != nil {
						t.Fatal("succeeded with inconsistent files", e)
					}
					if _, e = w.once(); e != nil {
						t.Fatal("completed job not idle", e)
					}
					if action == "disable" && state != "disabled" || action == "delete" && state != "deleted" || (action == "enable" || action == "rotate" || action == "create") && state != "active" {
						t.Fatal("wrong effective state")
					}
				} else if phase == "reconcile_required" {
					if !caddy.ConfigEqual(live, before) && !caddy.ConfigEqual(live, expected) {
						t.Fatal("unknown live state in controlled fixture")
					}
					if _, e = w.once(); e == nil {
						t.Fatal("ambiguous operation did not block queue")
					}
					if point == "after_rollback_verify" && !caddy.ConfigEqual(before, live) {
						t.Fatal("rollback lost old live state")
					}
				} else {
					t.Fatal("unresolved unblocked status", phase)
				}
			})
		}
	}
}
