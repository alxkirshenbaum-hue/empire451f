package caddy

import (
	"context"
	"errors"
	"os"
	"testing"
)

func TestAuthChangeLifecycle(t *testing.T) {
	ctx := context.Background()
	initial, err := PatchCreate(fixtureConfig(), "Alice", "old")
	if err != nil {
		t.Fatal(err)
	}
	r := &memoryRuntime{config: initial}
	for _, tc := range []struct {
		name   string
		change AuthChange
	}{
		{"disable", AuthChange{"Alice", "old", ""}},
		{"enable", AuthChange{"Alice", "", "old"}},
		{"rotate", AuthChange{"Alice", "old", "new"}},
		{"delete", AuthChange{"Alice", "new", ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]byte(nil), r.config...)
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			p, err := PrepareAuth(ctx, r, dir, "op", 2, tc.change)
			if err != nil {
				t.Fatal(err)
			}
			defer p.Clear()
			expected := fixtureConfig()
			if tc.change.Password != "" {
				expected, err = PatchCreate(expected, "Alice", tc.change.Password)
				if err != nil {
					t.Fatal(err)
				}
			}
			verify := func(context.Context) error {
				if !ConfigEqual(r.config, expected) {
					return ErrDrift
				}
				return nil
			}
			loads := r.loads
			if err := p.Apply(ctx, r, verify); err != nil {
				t.Fatal(err)
			}
			recovered, err := ReadPrepared(dir, "op", 2)
			if err != nil {
				t.Fatal(err)
			}
			defer recovered.Clear()
			if err := recovered.Verify(ctx, r, verify); err != nil {
				t.Fatal(err)
			}
			if r.loads != loads+1 {
				t.Fatal("recovery repeated load")
			}
			if err := recovered.Rollback(ctx, r, func(context.Context) error {
				if !ConfigEqual(r.config, before) {
					return ErrDrift
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			// Continue the lifecycle from the verified candidate.
			r.config = append([]byte(nil), expected...)
		})
	}
}

func TestAuthChangeRejectsDriftAndAmbiguity(t *testing.T) {
	raw, err := PatchCreate(fixtureConfig(), "Alice", "old")
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []AuthChange{
		{"Alice", "wrong", "new"}, {"alice", "old", ""}, {"missing", "old", "new"},
	} {
		if _, err := PatchAuth(raw, change); !errors.Is(err, ErrDrift) {
			t.Fatal("expected drift", err)
		}
	}
	if _, err := PatchAuth(fixtureConfig(), AuthChange{"canary", "old", ""}); !errors.Is(err, ErrInput) {
		t.Fatal("allowed empty authentication list", err)
	}
	if _, err := PatchAuth(raw, AuthChange{"Alice", "", "new"}); !errors.Is(err, ErrInput) {
		t.Fatal("insert replaced existing credential", err)
	}
	// Exact case remains independently addressable.
	if _, err := PatchAuth(raw, AuthChange{"alice", "", "other"}); err != nil {
		t.Fatal(err)
	}
}

type lostAckRuntime struct{ memoryRuntime }

func (r *lostAckRuntime) Load(ctx context.Context, b []byte) error {
	if err := r.memoryRuntime.Load(ctx, b); err != nil {
		return err
	}
	return errors.New("load acknowledgement lost")
}
func TestLostAcknowledgementUsesObservedProof(t *testing.T) {
	ctx := context.Background()
	rt := &lostAckRuntime{memoryRuntime{config: fixtureConfig()}}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(ctx, rt, dir, "op", 1, "new", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Clear()
	calls := 0
	if err = p.Apply(ctx, rt, func(context.Context) error { calls++; return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || rt.loads != 1 {
		t.Fatal("uncertain response was not inspected")
	}
	if _, err = PatchCreate(fixtureConfig(), "new", ""); !errors.Is(err, ErrInput) {
		t.Fatal("empty create password")
	}
}
