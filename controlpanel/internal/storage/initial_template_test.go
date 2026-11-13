package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestInitialTemplateIsImmutableAndReplaySafe(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	registry := openTest(t, filepath.Join(dir, "state.db"))
	body, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = registry.InstallInitialSFA(ctx, body, "wrong"); !errors.Is(err, ErrLegacyDrift) {
		t.Fatal("ignored approval digest", err)
	}
	revision, err := registry.InstallInitialSFA(ctx, body, digest(body))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := registry.QueueCreate(ctx, "owner", replayKey, CreateRequest{Login: "Test-User", DisplayName: "Test User", TemplateRevisionID: revision, TargetClient: "sfa"})
	if err != nil {
		t.Fatal(err)
	}
	secret, err := registry.OpenForPurpose(ctx, rec.UserID, PrepareAuth)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	again, err := registry.InstallInitialSFA(ctx, body, digest(body))
	if err != nil || again != revision {
		t.Fatal("initialization changed revision", err)
	}
	after, err := registry.OpenForPurpose(ctx, rec.UserID, PrepareAuth)
	if err != nil || !bytes.Equal(secret, after) {
		t.Fatal("initialization changed credential", err)
	}
	clear(after)
	changed := append(append([]byte(nil), body...), '\n')
	if _, err = registry.InstallInitialSFA(ctx, changed, digest(changed)); !errors.Is(err, ErrLegacyConflict) {
		t.Fatal("replaced a populated registry template", err)
	}
}
