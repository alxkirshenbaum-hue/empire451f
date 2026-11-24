package caddy

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func credential(login, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(base64.StdEncoding.EncodeToString([]byte(login + ":" + password))))
}

func fixtureConfig() []byte {
	b, _ := json.Marshal(map[string]any{"admin": map[string]any{"listen": "unix//private/admin.sock"}, "future": json.Number("9007199254740993"), "routes": []any{
		map[string]any{"handler": "forward_proxy", "auth_credentials": []string{credential("canary", "old")}, "upstream": "http://127.0.0.1:1081", "hide_ip": true},
		map[string]any{"handler": "static_response", "body": "unchanged"},
	}})
	return b
}

type memoryRuntime struct {
	config      []byte
	loads       int
	validateErr error
}

func (r *memoryRuntime) Read(context.Context) ([]byte, error) {
	return append([]byte(nil), r.config...), nil
}
func (r *memoryRuntime) Validate(context.Context, []byte) error { return r.validateErr }
func (r *memoryRuntime) Load(_ context.Context, b []byte) error {
	r.loads++
	r.config = append([]byte(nil), b...)
	return nil
}

func TestManagedOnlyAndRecovery(t *testing.T) {
	ctx := context.Background()
	before := fixtureConfig()
	r := &memoryRuntime{config: before}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	p, err := Prepare(ctx, r, dir, "op", 4, "New-User", "new secret")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Clear()
	// Removing exactly the appended credential must reproduce every old property.
	var patched map[string]any
	d := json.NewDecoder(bytes.NewReader(p.Candidate))
	d.UseNumber()
	if err = d.Decode(&patched); err != nil {
		t.Fatal(err)
	}
	h := patched["routes"].([]any)[0].(map[string]any)
	creds := h["auth_credentials"].([]any)
	if len(creds) != 2 || creds[1] != credential("New-User", "new secret") {
		t.Fatal("incorrect candidate auth")
	}
	h["auth_credentials"] = creds[:1]
	restored, _ := json.Marshal(patched)
	if !same(before, restored) {
		t.Fatal("unmanaged configuration changed")
	}
	if _, err = ReadPrepared(dir, "op", 5); !errors.Is(err, ErrDrift) {
		t.Fatal("ignored generation")
	}
	if _, err = Prepare(ctx, r, dir, "op", 4, "other", "secret"); err == nil {
		t.Fatal("overwrote durable preparation")
	}
	verifyCalls := 0
	verify := func(context.Context) error { verifyCalls++; return nil }
	if err = p.Apply(ctx, r, verify); err != nil {
		t.Fatal(err)
	}
	loaded, err := ReadPrepared(dir, "op", 4)
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Clear()
	if err = loaded.Verify(ctx, r, verify); err != nil || r.loads != 1 || verifyCalls != 2 {
		t.Fatal("recovery reapplied candidate", err)
	}
	if err = loaded.Rollback(ctx, r, verify); err != nil || !same(before, r.config) {
		t.Fatal("rollback failed", err)
	}
	if err = loaded.Rollback(ctx, r, verify); err != nil || r.loads != 2 {
		t.Fatal("rollback replay reloaded", err)
	}
}

func TestAdapterStopsOnDriftAndValidationFailure(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	_ = os.Chmod(dir, 0700)
	r := &memoryRuntime{config: fixtureConfig(), validateErr: ErrRuntime}
	if _, err := Prepare(ctx, r, dir, "op", 1, "new", "secret"); err == nil {
		t.Fatal("ignored validation")
	}
	if _, err := os.Stat(dir + "/prepared.json"); !os.IsNotExist(err) {
		t.Fatal("prepared invalid configuration")
	}
	r.validateErr = nil
	p, err := Prepare(ctx, r, dir, "op", 1, "new", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Clear()
	r.config = []byte(`{"external":"change"}`)
	probe := func(context.Context) error { t.Fatal("probed drifted config"); return nil }
	if !errors.Is(p.Apply(ctx, r, probe), ErrDrift) || !errors.Is(p.Verify(ctx, r, probe), ErrDrift) || !errors.Is(p.Rollback(ctx, r, probe), ErrDrift) || r.loads != 0 {
		t.Fatal("overwrote external change")
	}
	if _, err = PatchCreate(fixtureConfig(), "canary", "replacement"); err == nil {
		t.Fatal("replaced existing credential")
	}
	if _, err = PatchCreate(append(fixtureConfig(), []byte(" {}")...), "new", "secret"); err == nil {
		t.Fatal("accepted trailing JSON")
	}
}

func TestVerifyFailureAndConcurrentChange(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	r := &memoryRuntime{config: fixtureConfig()}
	p, err := Prepare(ctx, r, dir, "op", 1, "new", "secret")
	if err != nil {
		t.Fatal(err)
	}
	defer p.Clear()
	failure := errors.New("fresh connection failed")
	if err = p.Apply(ctx, r, func(context.Context) error { return failure }); !errors.Is(err, failure) {
		t.Fatal("ignored failed verification")
	}
	// Verification failure never implies successful rollback or another load.
	if r.loads != 1 || !same(r.config, p.Candidate) {
		t.Fatal("silently changed uncertain state")
	}
	if err = p.Verify(ctx, r, func(context.Context) error {
		r.config = []byte(`{"external":"changed during probe"}`)
		return nil
	}); !errors.Is(err, ErrDrift) {
		t.Fatal("missed concurrent change")
	}
	if err = p.Rollback(ctx, r, func(context.Context) error { return nil }); !errors.Is(err, ErrDrift) || r.loads != 1 {
		t.Fatal("destroyed external change")
	}
}
