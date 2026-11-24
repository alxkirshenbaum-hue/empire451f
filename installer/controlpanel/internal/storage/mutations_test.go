package storage

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func mutationFixture(t *testing.T) (string, *Registry, Receipt) {
	t.Helper()
	path, r := fixture(t)
	rec, err := r.QueueCreate(ctx, "owner", id(), request)
	if err != nil {
		t.Fatal(err)
	}
	if err = r.ApplyCreate(ctx, rec, func(context.Context, string, vault.PlainSecret) error { return nil }); err != nil {
		t.Fatal(err)
	}
	_, err = r.db.Exec("INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES('mutation-run','verified_cutover','{}','now','verified_cutover')")
	if err != nil {
		t.Fatal(err)
	}
	return path, r, rec
}
func TestMutationAdmissionAndSecretReplay(t *testing.T) {
	path, r, created := mutationFixture(t)
	req := MutationRequest{UserID: created.UserID, Action: "rotate", ExpectedVersion: 2, Reason: "owner request"}
	key := id()
	rec, err := r.QueueOwnedMutation(ctx, "mutation-run", "owner", key, req)
	if err != nil {
		t.Fatal(err)
	}
	job, err := r.OwnedAuthJob(ctx, "mutation-run", rec.OperationID)
	if err != nil {
		t.Fatal(err)
	}
	var old, fresh []byte
	if err = r.WithMutationSecrets(ctx, job, func(_ string, a, b vault.PlainSecret) error { old = bytes.Clone(a); fresh = bytes.Clone(b); return nil }); err != nil {
		t.Fatal(err)
	}
	defer clear(old)
	defer clear(fresh)
	if bytes.Equal(old, fresh) {
		t.Fatal("rotation reused old secret")
	}
	r.Close()
	r = openTest(t, path)
	replay, err := r.QueueOwnedMutation(ctx, "mutation-run", "owner", key, req)
	if err != nil || replay != rec {
		t.Fatal("replay", err)
	}
	if err = r.WithMutationSecrets(ctx, job, func(_ string, a, b vault.PlainSecret) error {
		if !bytes.Equal(old, a) || !bytes.Equal(fresh, b) {
			t.Fatal("replay generated secret")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	active, err := r.OpenForPurpose(ctx, created.UserID, RenderProfile)
	if err != nil || !bytes.Equal(old, active) {
		t.Fatal("published staged credential", err)
	}
	clear(active)
	if _, err = r.QueueOwnedMutation(ctx, "mutation-run", "owner", id(), req); !errors.Is(err, ErrOperationInProgress) {
		t.Fatal("conflicting rotate admitted", err)
	}
	req.Reason = "changed"
	if _, err = r.QueueOwnedMutation(ctx, "mutation-run", "owner", key, req); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatal("changed request replayed", err)
	}
	if err = r.Transition(ctx, rec.OperationID, "queued", "running"); err != nil {
		t.Fatal(err)
	}
	if err = r.Transition(ctx, rec.OperationID, "running", "verifying"); err != nil {
		t.Fatal(err)
	}
	if err = r.CompleteVerifiedMutation(ctx, "mutation-run", job); err != nil {
		t.Fatal(err)
	}
	if err = r.CompleteVerifiedMutation(ctx, "mutation-run", job); err != nil {
		t.Fatal("commit replay", err)
	}
	active, err = r.OpenForPurpose(ctx, created.UserID, RenderProfile)
	if err != nil || !bytes.Equal(fresh, active) {
		t.Fatal("rotation not committed", err)
	}
	clear(active)
	var revoked int
	if err = r.db.QueryRow("SELECT count(*) FROM credentials WHERE user_id=? AND revoked_at IS NOT NULL", created.UserID).Scan(&revoked); err != nil || revoked != 1 {
		t.Fatal("old not retained revoked", err)
	}
}
func TestMutationConcurrentAdmission(t *testing.T) {
	path, r, created := mutationFixture(t)
	other := openTest(t, path)
	start := make(chan struct{})
	results := make(chan error, 2)
	var wg sync.WaitGroup
	for i, client := range []*Registry{r, other} {
		wg.Add(1)
		go func(i int, client *Registry) {
			defer wg.Done()
			<-start
			action := "disable"
			if i == 1 {
				action = "rotate"
			}
			_, err := client.QueueOwnedMutation(ctx, "mutation-run", "owner", id(), MutationRequest{UserID: created.UserID, Action: action, ExpectedVersion: 2, Reason: "concurrent"})
			results <- err
		}(i, client)
	}
	close(start)
	wg.Wait()
	a, b := <-results, <-results
	if !(a == nil && errors.Is(b, ErrOperationInProgress) || b == nil && errors.Is(a, ErrOperationInProgress)) {
		t.Fatal("not serialized", a, b)
	}
}
func TestMutationLifecycleAndProtection(t *testing.T) {
	_, r, created := mutationFixture(t)
	_, err := r.db.Exec("INSERT INTO users(id,login,kind,protected,source,display_name,status,created_at,updated_at) VALUES('master','master_user','service',1,'legacy_import','master','active','now','now')")
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range []string{"disable", "enable", "rotate", "delete", "revoke"} {
		_, err = r.QueueOwnedMutation(ctx, "mutation-run", "owner", id(), MutationRequest{UserID: "master", Action: action, ExpectedVersion: 1, Reason: "test", ConfirmDelete: true})
		if !errors.Is(err, ErrProtectedAccount) {
			t.Fatal("protected", action, err)
		}
	}
	version := int64(2)
	for _, action := range []string{"disable", "disable", "enable", "rotate", "delete"} {
		rec, err := r.QueueOwnedMutation(ctx, "mutation-run", "owner", id(), MutationRequest{UserID: created.UserID, Action: action, ExpectedVersion: version, Reason: "test", ConfirmDelete: true})
		if err != nil {
			t.Fatal(action, err)
		}
		job, err := r.OwnedAuthJob(ctx, "mutation-run", rec.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		if err = r.Transition(ctx, rec.OperationID, "queued", "running"); err != nil {
			t.Fatal(err)
		}
		if err = r.Transition(ctx, rec.OperationID, "running", "verifying"); err != nil {
			t.Fatal(err)
		}
		if err = r.CompleteVerifiedMutation(ctx, "mutation-run", job); err != nil {
			t.Fatal(action, err)
		}
		if !job.NoChange {
			version++
		}
	}
	if _, err = r.QueueOwnedMutation(ctx, "mutation-run", "owner", id(), MutationRequest{UserID: created.UserID, Action: "enable", ExpectedVersion: version}); !errors.Is(err, ErrInvalidTransition) {
		t.Fatal("enabled tombstone", err)
	}
	duplicate := request
	if _, err = r.QueueCreate(ctx, "owner", id(), duplicate); err == nil {
		t.Fatal("reused tombstoned login")
	}
}

func TestMutationDoesNotAdvertiseUncertainEffectiveState(t *testing.T) {
	_, r, created := mutationFixture(t)
	rec, err := r.QueueOwnedMutation(ctx, "mutation-run", "owner", id(), MutationRequest{UserID: created.UserID, Action: "disable", ExpectedVersion: 2, Reason: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Transition(ctx, rec.OperationID, "queued", "running"); err != nil {
		t.Fatal(err)
	}
	for _, phase := range []string{"running", "reconcile_required"} {
		if phase == "reconcile_required" {
			if err = r.Transition(ctx, rec.OperationID, "running", phase); err != nil {
				t.Fatal(err)
			}
		}
		u, err := r.GetUser(ctx, created.UserID)
		if err != nil || u.Status != "reconcile_required" {
			t.Fatal("advertised effective state", u.Status, err)
		}
		page, err := r.ListUsers(ctx, 100, 0)
		if err != nil || len(page) != 1 || page[0].Status != "reconcile_required" {
			t.Fatal("list advertised active state", err)
		}
		var durable string
		if err = r.db.QueryRow("SELECT status FROM users WHERE id=?", created.UserID).Scan(&durable); err != nil || durable != "active" {
			t.Fatal("destroyed recovery prestate", err)
		}
	}
}
