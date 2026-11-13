//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestWorkerPolicyAndProbeBoundary(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root policy test")
	}
	bin, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	bin, err = filepath.EvalSymlinks(bin)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "worker.json")
	run := "a9b5c248-884a-40f0-823a-4dae9a541e3b"
	p := workerPolicy{Installation: "lab", OwnerRun: run, Socket: filepath.Join(dir, "socket"), Helper: bin, Validate: []string{bin}, Probe: []string{bin}}
	put := func(p workerPolicy) {
		t.Helper()
		data, _ := json.Marshal(p)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	put(p)
	if _, err = readWorkerPolicy(path, "lab", run); err != nil {
		t.Fatal(err)
	}
	if _, err = readWorkerPolicy(path, "lab", "other"); err == nil {
		t.Fatal("ignored owner run")
	}
	if err = os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err = readWorkerPolicy(path, "lab", run); err == nil {
		t.Fatal("accepted public policy")
	}
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	p.Probe = []string{"relative-program"}
	put(p)
	if _, err = readWorkerPolicy(path, "lab", run); err == nil {
		t.Fatal("accepted relative executable")
	}
	var stdout, stderr bytes.Buffer
	if code := execute([]string{"worker", "once", "--installation", "../wrong", "--owner-run", run}, &stdout, &stderr); code != 2 {
		t.Fatal("accepted invalid installation")
	}
	// A subprocess failure never includes its stderr/secret in a returned error.
	secret := vault.PlainSecret("synthetic secret")
	probe := commandProbe([]string{"/bin/sh", "-c", "cat >&2; exit 1"})
	err = probe(context.Background(), "Test-User", secret)
	if err == nil || bytes.Contains([]byte(err.Error()), secret) {
		t.Fatal("probe leaked secret or ignored error")
	}
}
