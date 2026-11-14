//go:build linux

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifyOwnedFilesPreservesLargeManagedFile(t *testing.T) {
	root := t.TempDir()
	state, config := filepath.Join(root, "lab"), filepath.Join(root, "config")
	for _, dir := range []string{state, filepath.Join(config, "lab")} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	managed := filepath.Join(root, "large-artifact")
	f, err := os.OpenFile(managed, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err = f.Truncate(33 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, f); err != nil {
		t.Fatal(err)
	}
	auth := []byte("synthetic auth\n")
	if err = os.WriteFile(filepath.Join(config, "lab", "auth.caddy"), auth, 0600); err != nil {
		t.Fatal(err)
	}
	authHash := sha256.Sum256(auth)
	manifest := map[string]any{
		"config": map[string]string{"id": "lab"}, "panel_generation": 1,
		"panel_run_id": "fixture-run", "panel_auth_hash": hex.EncodeToString(authHash[:]),
		"files": map[string]string{managed: hex.EncodeToString(hash.Sum(nil))},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(state, "manifest.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	if generation, err := verifyOwnedFiles(state, config, "fixture-run"); err != nil || generation != 1 {
		t.Fatalf("ordinary verification rejected large managed file: generation=%d err=%v", generation, err)
	}
	// The binding calls this observer with its snapshot-only resource policy.
	if _, err := observeOwnedFiles(state, config, "fixture-run", true); err == nil {
		t.Fatal("snapshot observation accepted oversized managed file")
	}
}
