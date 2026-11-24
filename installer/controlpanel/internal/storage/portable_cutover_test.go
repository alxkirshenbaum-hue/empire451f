package storage

import (
	"context"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"strings"
	"testing"
)

func TestPortableCutoverPreservesStatusesAndBoundResume(t *testing.T) {
	source, key, owner := portableSourceFixture(t)
	dest := portableDestinationFixture(t)
	plan, e := dest.PreviewPortable(ctx, source, key.vault, owner, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = dest.ImportPortable(ctx, source, key.vault, owner, "", plan.Hash, true); e != nil {
		t.Fatal(e)
	}
	run := id()
	baseline := strings.Repeat("1", 64)
	receipt, e := dest.BeginPortableCutover(ctx, run, plan.Hash, baseline)
	if e != nil {
		t.Fatal(e)
	}
	if _, _, e = dest.PortableCutoverState(ctx, run, plan.Hash, strings.Repeat("2", 64)); e == nil {
		t.Fatal("wrong beforeimage accepted")
	}
	if _, _, e = dest.PortableCutoverState(ctx, run, plan.Hash, baseline); e != nil {
		t.Fatal(e)
	}
	positives, negatives := 0, 0
	probe := func(_ context.Context, login string, secret vault.PlainSecret, active bool) error {
		if len(secret) == 0 {
			t.Fatal("missing probe credential")
		}
		if login == "alex" && active {
			t.Fatal("disabled user activated")
		}
		if active {
			positives++
		} else {
			negatives++
		}
		return nil
	}
	injected := errors.New("partial application")
	if _, e = dest.CompletePortableCutover(ctx, run, probe, func(context.Context) error { return injected }); !errors.Is(e, injected) {
		t.Fatal(e)
	}
	_, phase, e := dest.PortableCutoverState(ctx, run, plan.Hash, baseline)
	if e != nil || phase != "running" {
		t.Fatal("unsafe partial finalize", phase, e)
	}
	done, e := dest.CompletePortableCutover(ctx, run, probe, func(context.Context) error { return nil })
	if e != nil || done.OperationID != receipt.OperationID {
		t.Fatal(e)
	}
	if positives == 0 || negatives == 0 {
		t.Fatal("probe matrix incomplete")
	}
	var state string
	if e = dest.db.QueryRow("SELECT status FROM users WHERE login='alex'").Scan(&state); e != nil || state != "disabled" {
		t.Fatal("disabled status changed", e)
	}
	_, phase, e = dest.PortableCutoverState(ctx, run, plan.Hash, baseline)
	if e != nil || phase != "succeeded" {
		t.Fatal(phase, e)
	}
}
