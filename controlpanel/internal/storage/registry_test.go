package storage

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

var ctx = context.Background()
var request = CreateRequest{"Test-User", "Synthetic fixture", "rev1", "sfa-1.14.4"}

const replayKey = "ee5903c0-bbd4-4eb2-aa4f-8a489c4884cf"

func openTest(t *testing.T, path string) *Registry {
	t.Helper()
	v, err := vault.New(bytes.Repeat([]byte{7}, 32))
	if err != nil {
		t.Fatal(err)
	}
	r, err := Open(ctx, path, v, 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func fixture(t *testing.T) (string, *Registry) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "registry.db")
	r := openTest(t, path)
	_, err := r.db.Exec("INSERT INTO profile_templates VALUES('template','sfa','SFA','naive_https',1); INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at) VALUES('rev1','template','1','sfa','1.14.4','{}','test','approved','now')")
	if err != nil {
		t.Fatal(err)
	}
	return path, r
}

func counts(t *testing.T, r *Registry, want int) {
	t.Helper()
	for _, table := range []string{"users", "credentials", "user_current_credentials", "operations", "user_profiles"} {
		var n int
		if err := r.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != want {
			t.Fatalf("%s: got %d, want %d", table, n, want)
		}
	}
}

func TestReplayAndConflict(t *testing.T) {
	path, r := fixture(t)
	other := openTest(t, path)
	type result struct {
		receipt Receipt
		err     error
	}
	answers := make(chan result, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for _, reg := range []*Registry{r, other} {
		wg.Add(1)
		go func(reg *Registry) {
			defer wg.Done()
			<-start
			x, e := reg.QueueCreate(ctx, "owner", replayKey, request)
			answers <- result{x, e}
		}(reg)
	}
	close(start)
	wg.Wait()
	a, b := <-answers, <-answers
	if a.err != nil || b.err != nil || a.receipt != b.receipt {
		t.Fatalf("replay failed: %v %v", a.err, b.err)
	}
	changed := request
	changed.TargetClient = "sfa-1.15-alpha13"
	if _, err := r.QueueCreate(ctx, "owner", replayKey, changed); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("conflict: %v", err)
	}
	counts(t, r, 1)
	var state, status string
	if err := r.db.QueryRow("SELECT u.status,o.status FROM users u JOIN operations o ON u.id=o.target_id WHERE o.id=?", a.receipt.OperationID).Scan(&state, &status); err != nil || state != "provisioning" || status != "queued" {
		t.Fatal("incorrect states", err)
	}
}

func TestPlaintextAbsentFromDatabaseAndLiveWAL(t *testing.T) {
	path, r := fixture(t)
	rec, err := r.QueueCreate(ctx, "owner", replayKey, request)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := r.loadCredential(ctx, rec.UserID)
	if err != nil || len(secret) != 43 {
		t.Fatal("failed to recover generated secret", err)
	}
	defer clear(secret)
	var busy, frames, copied int
	if err = r.db.QueryRow("PRAGMA wal_checkpoint(FULL)").Scan(&busy, &frames, &copied); err != nil || busy != 0 || frames <= 0 || frames != copied {
		t.Fatal("checkpoint failed", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		data, err := os.ReadFile(path + suffix)
		if err != nil || len(data) == 0 {
			t.Fatal("no evidence for "+suffix, err)
		}
		if suffix != "-shm" && !bytes.Contains(data, []byte(rec.UserID)) {
			t.Fatal("positive scan control missing: " + suffix)
		}
		if bytes.Contains(data, secret) {
			t.Fatal("plaintext in SQLite artifact " + suffix)
		}
	}
	if _, err = r.db.Exec("UPDATE users SET status='disabled' WHERE id=?", rec.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err = r.loadCredential(ctx, rec.UserID); !errors.Is(err, sql.ErrNoRows) {
		t.Fatal("disabled credential released")
	}
}

func TestCrashChild(t *testing.T) {
	phase := os.Getenv("REGISTRY_TEST_CRASH")
	if phase == "" {
		t.Skip("subprocess only")
	}
	r := openTest(t, os.Getenv("REGISTRY_TEST_PATH"))
	switch phase {
	case "before":
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.stageCreate(ctx, tx, "owner", replayKey, request); err != nil {
			t.Fatal(err)
		}
	case "after":
		if _, err := r.QueueCreate(ctx, "owner", replayKey, request); err != nil {
			t.Fatal(err)
		}
	default:
		t.Fatal("invalid phase")
	}
	os.Exit(86) // immediate process termination: skip Close, rollback and test cleanup
}

func TestCrashAndRetry(t *testing.T) {
	for _, phase := range []string{"before", "after"} {
		t.Run(phase, func(t *testing.T) {
			path, r := fixture(t)
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(os.Args[0], "-test.run=^TestCrashChild$")
			cmd.Env = append(os.Environ(), "REGISTRY_TEST_CRASH="+phase, "REGISTRY_TEST_PATH="+path)
			var childErr *exec.ExitError
			if err := cmd.Run(); !errors.As(err, &childErr) || childErr.ExitCode() != 86 {
				t.Fatalf("child failed before crash point: %v", err)
			}
			r = openTest(t, path)
			want := 0
			var before Receipt
			if phase == "after" {
				want = 1
				if err := r.db.QueryRow("SELECT id,target_id FROM operations").Scan(&before.OperationID, &before.UserID); err != nil {
					t.Fatal(err)
				}
			}
			counts(t, r, want)
			got, err := r.QueueCreate(ctx, "owner", replayKey, request)
			if err != nil || (want == 1 && got != before) {
				t.Fatal("crash replay failed", err)
			}
			counts(t, r, 1)
			if _, err = r.loadCredential(ctx, got.UserID); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMigrationChecksAndPermissions(t *testing.T) {
	path, r := fixture(t)
	wrong, err := vault.New(bytes.Repeat([]byte{8}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if bad, err := Open(ctx, path, wrong, 1); err == nil {
		bad.Close()
		t.Fatal("accepted wrong vault key")
	}
	if _, err := r.db.Exec("UPDATE schema_migrations SET sha256='changed'"); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	v, err := vault.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	if db, err := Open(ctx, path, v, 1); err == nil {
		db.Close()
		t.Fatal("accepted altered migration")
	}
	if runtime.GOOS != "windows" {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if db, err := Open(ctx, filepath.Join(dir, "registry.db"), v, 1); err == nil {
			db.Close()
			t.Fatal("accepted shared directory")
		}
	}
}

func TestUpgradePopulatedVersionOne(t *testing.T) {
	path, r := fixture(t)
	record, err := r.QueueCreate(ctx, "owner", replayKey, request)
	if err != nil {
		t.Fatal(err)
	}
	before, err := r.loadCredential(ctx, record.UserID)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(before)
	// Reproduce the exact prior schema and migration history, retaining the rows.
	_, err = r.db.Exec("BEGIN IMMEDIATE; DROP TABLE legacy_migration_documents; DROP TABLE vault_identity; DELETE FROM schema_migrations WHERE version>=2; COMMIT;")
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := vault.New(bytes.Repeat([]byte{9}, 32))
	if err != nil {
		t.Fatal(err)
	}
	if bad, err := Open(ctx, path, wrong, 1); err == nil {
		bad.Close()
		t.Fatal("legacy vault accepted wrong key")
	}
	var version int
	if err := r.db.QueryRow("SELECT max(version) FROM schema_migrations").Scan(&version); err != nil || version != 1 {
		t.Fatal("partial upgrade", err)
	}
	next := openTest(t, path)
	after, err := next.loadCredential(ctx, record.UserID)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("upgrade did not preserve credential", err)
	}
	clear(after)
	counts(t, next, 1)
}
