//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

var installationID = regexp.MustCompile("^[a-z][a-z0-9]{2,9}$")

func createLocalUser(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("user create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	deployment := flags.String("installation", "", "Installer deployment")
	run := flags.String("owner-run", "", "Expected writer migration")
	login := flags.String("login", "", "Exact VPN login")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !installationID.MatchString(*deployment) || !status.ValidID(*run) {
		fmt.Fprintln(stderr, "Invalid installation or owner run")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Run as root on the entry")
		return 3
	}
	receipt, err := queueFromInstallation(filepath.Join("/var/lib/empire-vpn", *deployment), "/etc/empire-vpn", "/run/lock/empire-vpn.lock", "/var/lib/vpn-control", *run, *login)
	if err != nil {
		fmt.Fprintln(stderr, "Cannot queue user creation; check writer ownership, VPN state, login and approved SFA template")
		return 4
	}
	fmt.Fprintf(out, "User creation operation: %s\n", receipt.OperationID)
	return 0
}

func queueFromInstallation(state, config, lockPath, panel, run, login string) (storage.Receipt, error) {
	return withOwnedInstallation(state, config, lockPath, panel, run, func(ctx context.Context, registry *storage.Registry) (storage.Receipt, error) {
		// One SSH request per exact login and owner run. Tombstones reserve that name.
		token := sha256.Sum256([]byte(run + "\x00ssh-create\x00" + login))
		token[6] = token[6]&15 | 80
		token[8] = token[8]&63 | 128
		requestID := fmt.Sprintf("%x-%x-%x-%x-%x", token[:4], token[4:6], token[6:8], token[8:10], token[10:16])
		return registry.QueueOwnedCreate(ctx, run, "local-ssh", requestID, login)
	})
}

// runNextCreate keeps the same installation lock and preconditions as the SSH
// queue entry point for the entire apply/verify/commit cycle. The adapter must
// check its durable candidate and live Caddy state before recovering a job.
func runNextCreate(state, config, lockPath, panel, run string, apply, verify func(context.Context, string, vault.PlainSecret) error) (storage.Receipt, error) {
	return withOwnedInstallation(state, config, lockPath, panel, run, func(ctx context.Context, registry *storage.Registry) (storage.Receipt, error) {
		receipt, phase, err := registry.NextOwnedCreate(ctx, run)
		if err != nil || phase == "" {
			return receipt, err
		}
		if phase == "queued" {
			err = registry.ApplyCreate(ctx, receipt, apply)
		} else {
			err = registry.RecoverCreate(ctx, receipt, verify)
		}
		return receipt, err
	})
}

func withOwnedInstallation(state, config, lockPath, panel, run string, action func(context.Context, *storage.Registry) (storage.Receipt, error)) (storage.Receipt, error) {
	return withOwnedInstallationRecovery(state, config, lockPath, panel, run, nil, action)
}

// Recovery runs under the same lock before the ordinary file check. It may
// repair only a bound, inspected pending saga; normal callers cannot bypass drift.
func withOwnedInstallationRecovery(state, config, lockPath, panel, run string, recovery func(context.Context, *storage.Registry) error, action func(context.Context, *storage.Registry) (storage.Receipt, error)) (storage.Receipt, error) {
	var empty storage.Receipt
	lock, err := installationLock(lockPath)
	if err != nil {
		return empty, err
	}
	defer lock.Close()
	for _, journal := range []string{"pending.json", "user-rollback.json", "return-intent.json"} {
		if _, err = os.Lstat(filepath.Join(state, journal)); !errors.Is(err, os.ErrNotExist) {
			return empty, storage.ErrLegacyConflict
		}
	}
	ctx := context.Background()
	registry, err := openExistingRegistry(ctx, filepath.Join(panel, "state.db"), filepath.Join(panel, "vault.key"), 1)
	if err != nil {
		return empty, err
	}
	defer registry.Close()
	if _, err = os.Lstat(filepath.Join(state, "panel-auth-pending.json")); !errors.Is(err, os.ErrNotExist) {
		if err != nil || recovery == nil {
			return empty, storage.ErrLegacyConflict
		}
		if err = recovery(ctx, registry); err != nil {
			return empty, err
		}
	}
	if _, err = verifyOwnedFiles(state, config, run); err != nil {
		return empty, err
	}
	return action(ctx, registry)
}

func verifyOwnedFiles(state, config, run string) (int64, error) {
	data, err := os.ReadFile(filepath.Join(state, "manifest.json"))
	if err != nil {
		return 0, err
	}
	var manifest struct {
		Generation int64             `json:"panel_generation"`
		Run        string            `json:"panel_run_id"`
		Hash       string            `json:"panel_auth_hash"`
		Files      map[string]string `json:"files"`
		Config     struct {
			ID string `json:"id"`
		} `json:"config"`
	}
	err = json.Unmarshal(data, &manifest)
	auth := filepath.Join(config, filepath.Base(state), "auth.caddy")
	_, legacy := manifest.Files[auth]
	if err != nil || manifest.Files == nil || legacy || manifest.Config.ID != filepath.Base(state) || manifest.Generation < 1 || manifest.Run != run {
		return 0, storage.ErrLegacyConflict
	}
	content, err := os.ReadFile(auth)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(content)
	clear(content)
	if hex.EncodeToString(sum[:]) != manifest.Hash {
		return 0, storage.ErrLegacyDrift
	}
	for path, expected := range manifest.Files {
		data, e := os.ReadFile(path)
		if e != nil {
			return 0, storage.ErrLegacyDrift
		}
		digest := sha256.Sum256(data)
		clear(data)
		if hex.EncodeToString(digest[:]) != expected {
			return 0, storage.ErrLegacyDrift
		}
	}
	return manifest.Generation, nil
}
