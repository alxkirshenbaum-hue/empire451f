package storage

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// The source registry retains its valid key while capture receives a separately
// observed key. This prevents source-open validation from masking a missing
// copied-database key check.
func TestCaptureOwnedSnapshotObservedKey(t *testing.T) {
	for _, scenario := range []string{"valid", "wrong-key", "missing-owner", "empty-owner", "nil-key"} {
		t.Run(scenario, func(t *testing.T) {
			_, r, _ := snapshotFixture(t)
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			sentry := filepath.Join(directory, "sentry")
			if err := os.WriteFile(sentry, []byte("unchanged"), 0600); err != nil {
				t.Fatal(err)
			}
			run := "mutation-run"
			observed := r.vault
			var want error
			switch scenario {
			case "wrong-key":
				var err error
				observed, err = vault.New(bytes.Repeat([]byte{213}, 32))
				if err != nil {
					t.Fatal(err)
				}
				want = ErrVaultKey
			case "missing-owner":
				run = "missing-owner"
				want = ErrLegacyConflict
			case "empty-owner":
				run = ""
			case "nil-key":
				observed = nil
			}
			got, err := r.CaptureOwnedSnapshot(context.Background(), directory, "", run, observed)
			if scenario == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(got.Path); err != nil {
					t.Fatal(err)
				}
				if filepath.Dir(got.Path) == directory {
					t.Fatal("capture lacks private child")
				}
			} else {
				if err == nil {
					t.Fatal("unbound capture accepted")
				}
				if want != nil && !errors.Is(err, want) {
					t.Fatalf("error %v; want %v", err, want)
				}
				entries, e := os.ReadDir(directory)
				if e != nil || len(entries) != 1 || entries[0].Name() != "sentry" {
					t.Fatalf("capture leaked staging: %v %v", entries, e)
				}
			}
			b, e := os.ReadFile(sentry)
			if e != nil || string(b) != "unchanged" {
				t.Fatalf("sibling changed: %v", e)
			}
		})
	}
}
