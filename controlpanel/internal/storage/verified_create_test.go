package storage

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestRecoverCreate(t *testing.T) {
	for _, phase := range []string{"running", "verifying"} {
		t.Run(phase, func(t *testing.T) {
			path, r := fixture(t)
			rec, err := r.QueueCreate(ctx, "owner", replayKey, request)
			if err != nil {
				t.Fatal(err)
			}
			before, err := r.OpenForPurpose(ctx, rec.UserID, PrepareAuth)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(before)
			if err = r.Transition(ctx, rec.OperationID, "queued", "running"); err != nil {
				t.Fatal(err)
			}
			if phase == "verifying" {
				if err = r.Transition(ctx, rec.OperationID, "running", phase); err != nil {
					t.Fatal(err)
				}
			}
			r.Close()
			r = openTest(t, path)
			calls := 0
			verify := func(_ context.Context, login string, secret vault.PlainSecret) error {
				calls++
				if login != request.Login || !bytes.Equal(before, secret) {
					t.Fatal("changed credential")
				}
				return nil
			}
			// Reproduce a failure after successful verification, before SQLite commit.
			if _, err = r.db.Exec("CREATE TRIGGER reject_finish BEFORE UPDATE OF status ON operations WHEN NEW.status='succeeded' BEGIN SELECT RAISE(ABORT,'fixture'); END"); err != nil {
				t.Fatal(err)
			}
			if r.RecoverCreate(ctx, rec, verify) == nil {
				t.Fatal("expected commit failure")
			}
			if _, err = r.OpenForPurpose(ctx, rec.UserID, RenderProfile); err == nil {
				t.Fatal("issued before commit")
			}
			if _, err = r.db.Exec("DROP TRIGGER reject_finish"); err != nil {
				t.Fatal(err)
			}
			if err = r.RecoverCreate(ctx, rec, verify); err != nil {
				t.Fatal(err)
			}
			if calls != 2 {
				t.Fatal("recovery did not reverify")
			}
			if err = r.CompleteVerifiedCreate(ctx, rec, 1); err != nil {
				t.Fatal(err)
			}
			counts(t, r, 1)
		})
	}
}

func TestOwnedCreateRecoveryBlocksQueue(t *testing.T) {
	_, r := fixture(t)
	run := "synthetic-run"
	if _, err := r.db.Exec("INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'verified_cutover','{}','now','verified_cutover')", run); err != nil {
		t.Fatal(err)
	}
	a, err := r.QueueCreate(ctx, "owner", replayKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.NextOwnedCreate(ctx, "wrong-run"); !errors.Is(err, ErrLegacyConflict) {
		t.Fatal("ignored owner")
	}
	if err = r.Transition(ctx, a.OperationID, "queued", "running"); err != nil {
		t.Fatal(err)
	}
	got, phase, err := r.NextOwnedCreate(ctx, run)
	if err != nil || got != a || phase != "running" {
		t.Fatal("lost interrupted operation", err)
	}
	probeErr := errors.New("probe failed")
	if err = r.RecoverCreate(ctx, a, func(context.Context, string, vault.PlainSecret) error { return probeErr }); !errors.Is(err, probeErr) {
		t.Fatal(err)
	}
	if _, _, err = r.NextOwnedCreate(ctx, run); !errors.Is(err, ErrJournalConflict) {
		t.Fatal("skipped uncertain operation")
	}
	if err = r.RecoverCreate(ctx, a, func(context.Context, string, vault.PlainSecret) error {
		t.Fatal("retried ambiguous operation")
		return nil
	}); err == nil {
		t.Fatal("reopened reconciliation")
	}
	if _, err = r.OpenForPurpose(ctx, a.UserID, RenderProfile); err == nil {
		t.Fatal("issued uncertain profile")
	}
}
