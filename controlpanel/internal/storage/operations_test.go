package storage

import (
	"errors"
	"testing"
	"time"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
)

func TestInterruptedJournal(t *testing.T) {
	path, r := fixture(t)
	receipt, err := r.QueueCreate(ctx, "owner", replayKey, request)
	if err != nil {
		t.Fatal(err)
	}
	op := receipt.OperationID
	other := openTest(t, path)
	move := func(from, to string) {
		t.Helper()
		if e := r.Transition(ctx, op, from, to); e != nil {
			t.Fatal(e)
		}
	}
	scan := func(want string, last int) {
		t.Helper()
		found, e := r.FindUnfinished(ctx)
		if e != nil {
			t.Fatal(e)
		}
		if want == "" {
			if len(found) != 0 {
				t.Fatal("unexpected interrupted operation")
			}
			return
		}
		if len(found) != 1 || found[0] != (InterruptedOperation{op, "user.create", want, last}) {
			t.Fatal("incorrect recovery cursor")
		}
	}
	scan("", 0)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, client := range []*Registry{r, other} {
		go func(reg *Registry) { <-start; results <- reg.Transition(ctx, op, "queued", "running") }(client)
	}
	close(start)
	a, b := <-results, <-results
	if !(a == nil && errors.Is(b, ErrJournalConflict) || b == nil && errors.Is(a, ErrJournalConflict)) {
		t.Fatal("two claimants", a, b)
	}
	now := time.Now().UTC()
	c := Checkpoint{Number: 1, Name: "prepare", State: "succeeded", Started: now, Finished: now}
	write := func(phase string, step Checkpoint, want error) {
		t.Helper()
		if e := r.AppendStep(ctx, op, phase, step); !errors.Is(e, want) {
			t.Fatalf("unexpected append result %v", e)
		}
	}
	write("running", c, nil)
	write("running", c, nil)
	conflict := c
	conflict.Name = "inspect"
	write("running", conflict, ErrJournalConflict)
	gap := c
	gap.Number = 3
	write("running", gap, ErrJournalConflict)
	bad := c
	bad.Name = "synthetic private input"
	write("running", bad, ErrInvalidStep)
	move("running", "verifying")
	step2 := c
	step2.Number = 2
	step2.Name = "verify"
	step2.State = "failed"
	step2.ErrorCode = "VERIFY_FAILED"
	write("running", step2, ErrJournalConflict)
	write("verifying", step2, nil)
	other.Close()
	r.Close()
	r = openTest(t, path)
	scan("verifying", 2)
	// Read checkpoints through the same owner-scoped query as the HTTP endpoint.
	_, err = r.db.Exec("INSERT INTO admin_accounts(id,username,password_hash,created_at) VALUES('owner','owner','fixture',CURRENT_TIMESTAMP)")
	if err != nil {
		t.Fatal(err)
	}
	_, err = r.db.Exec("INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at,last_seen_at) VALUES('fixture','owner',?,datetime('now','+1 hour'),CURRENT_TIMESTAMP)", digest([]byte("fixture-token")))
	if err != nil {
		t.Fatal(err)
	}
	reader, err := status.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	view, err := reader.Lookup(ctx, "fixture-token", op)
	if err != nil || len(view.Steps) != 2 || view.Steps[0].Name != "prepare" || view.Steps[1].Error == nil || *view.Steps[1].Error != "VERIFY_FAILED" {
		t.Fatal("lost OPS-02 checkpoint", err)
	}
	if e := r.Transition(ctx, op, "verifying", "cancelled"); !errors.Is(e, ErrJournalConflict) {
		t.Fatal("accepted late cancellation")
	}
	move("verifying", "rollback_running")
	scan("rollback_running", 2)
	move("rollback_running", "rolled_back")
	scan("", 0)
	write("verifying", step2, nil)
	if e := r.Transition(ctx, op, "rolled_back", "running"); !errors.Is(e, ErrJournalConflict) {
		t.Fatal("reopened terminal operation")
	}
	view, err = reader.Lookup(ctx, "fixture-token", op)
	if err != nil || view.Started == nil || view.Finished == nil || view.Status != "rolled_back" {
		t.Fatal("missing terminal timestamps")
	}
}
