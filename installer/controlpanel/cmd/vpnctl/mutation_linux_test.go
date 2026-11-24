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
	"path/filepath"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestCaddyMutationLifecycle(t *testing.T) {
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
	if _, err = w.once(); err != nil {
		t.Fatal(err)
	}
	w.mutationProbe = func(ctx context.Context, j storage.AuthJob, old, fresh vault.PlainSecret) error {
		current, e := rt.Read(ctx)
		if e != nil {
			return e
		}
		// Independent oracle checks fresh synthetic authentication values and canary.
		var config map[string]any
		if json.Unmarshal(current, &config) != nil {
			return caddy.ErrInput
		}
		creds := config["routes"].([]any)[0].(map[string]any)["auth_credentials"].([]any)
		values := map[string]bool{}
		for _, value := range creds {
			values[value.(string)] = true
		}
		encode := func(login string, p vault.PlainSecret) string {
			return base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(login + ":" + string(p)))))
		}
		if !values[double] {
			return errors.New("control credential changed")
		}
		active := j.AfterStatus == "active"
		if values[encode(j.Login, fresh)] != active {
			return errors.New("candidate authentication differs")
		}
		if j.Kind == "credential.rotate" && values[encode(j.Login, old)] {
			return errors.New("old credential retained")
		}
		return nil
	}
	version := int64(2)
	for _, action := range []string{"disable", "disable", "enable", "rotate", "delete"} {
		t.Run(action, func(t *testing.T) {
			cipher, _ := vault.New(key)
			reg, e := storage.Open(ctx, dbPath, cipher, 1)
			if e != nil {
				t.Fatal(e)
			}
			rec, e := reg.QueueOwnedMutation(ctx, run, "ssh-root", fmt.Sprintf("%s-%d", action, version), storage.MutationRequest{UserID: receipt.UserID, Action: action, ExpectedVersion: version, Reason: "test", ConfirmDelete: true})
			if e != nil {
				reg.Close()
				t.Fatal(e)
			}
			job, e := reg.OwnedAuthJob(ctx, run, rec.OperationID)
			reg.Close()
			if e != nil {
				t.Fatal(e)
			}
			beforeLoads := rt.loads
			// Interrupt the database completion after live proof, then recover in place.
			execSQL("CREATE TRIGGER reject_mutation_finish BEFORE UPDATE OF status ON operations WHEN NEW.status='succeeded' BEGIN SELECT RAISE(ABORT,'fixture'); END")
			if _, e = w.once(); e == nil {
				t.Fatal("commit failure missing")
			}
			execSQL("DROP TRIGGER reject_mutation_finish")
			afterApply := rt.loads
			if job.NoChange && afterApply != beforeLoads {
				t.Fatal("no-op reloaded Caddy")
			}
			if _, e = w.once(); e != nil {
				t.Fatal("recovery", e)
			}
			if rt.loads != afterApply {
				t.Fatal("recovery repeated load")
			}
			if !job.NoChange {
				version++
			}
			if _, e = os.Stat(filepath.Join(state, "panel-auth-pending.json")); !errors.Is(e, os.ErrNotExist) {
				t.Fatal("pending journal not cleaned", e)
			}
			if _, e = w.once(); e != nil {
				t.Fatal("idle", e)
			}
		})
	}
}
