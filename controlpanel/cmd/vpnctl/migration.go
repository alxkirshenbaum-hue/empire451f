package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func executeMigration(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("migration execute", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	run := flags.String("approved-plan", "", "Approved plan UUID")
	db := flags.String("staging-db", "", "Existing private staging registry")
	snapshot := flags.String("snapshot", "", "Offline snapshot directory")
	keyPath := flags.String("vault-key-file", "", "Private binary vault key file")
	version := flags.Int64("key-version", 1, "Vault key version")
	machine := flags.Bool("json", false, "Machine-readable result")
	quiet := flags.Bool("quiet", false, "Suppress success output")
	fail := func(exit int, code, message string) int {
		if *machine {
			if err := json.NewEncoder(out).Encode(struct {
				Error status.Problem `json:"error"`
			}{status.Problem{Code: code, Message: message}}); err != nil {
				return 9
			}
		} else {
			fmt.Fprintln(stderr, code, message)
		}
		return exit
	}
	if flags.Parse(args) != nil || flags.NArg() != 0 || !status.ValidID(*run) || *db == "" || *snapshot == "" || *keyPath == "" || *version < 1 || (*quiet && *machine) {
		return fail(2, "VALIDATION_ERROR", "Expected an approved plan UUID, staging DB, snapshot and key file")
	}
	info, err := os.Lstat(*db)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return fail(2, "VALIDATION_ERROR", "Existing staging registry required")
	}
	info, err = os.Lstat(*keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return fail(5, "SECRET_UNAVAILABLE", "Private 32-byte vault key file required")
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		return fail(5, "SECRET_UNAVAILABLE", "Vault key unavailable")
	}
	cipher, err := vault.New(key)
	clear(key)
	if err != nil {
		return fail(5, "SECRET_UNAVAILABLE", "Invalid vault key")
	}
	ctx := context.Background()
	registry, err := storage.Open(ctx, *db, cipher, *version)
	if err != nil {
		if errors.Is(err, storage.ErrVaultKey) {
			return fail(5, "SECRET_UNAVAILABLE", "Vault key verification failed")
		}
		return fail(5, "DEPENDENCY_UNAVAILABLE", "Cannot open staging registry")
	}
	defer registry.Close()
	receipt, err := registry.StageLegacy(ctx, *snapshot, *run)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrLegacyDrift):
			return fail(4, "CONFIG_DRIFT", "Snapshot differs from approved plan")
		case errors.Is(err, storage.ErrLegacyConflict):
			return fail(4, "VERSION_CONFLICT", "Plan cannot be applied to current state")
		case errors.Is(err, sql.ErrNoRows):
			return fail(2, "NOT_FOUND", "Migration plan unavailable")
		case errors.Is(err, storage.ErrLegacyInput), errors.Is(err, os.ErrNotExist):
			return fail(2, "VALIDATION_ERROR", "Incomplete snapshot")
		default:
			return fail(9, "INTERNAL_ERROR", "Staging failed")
		}
	}
	if *quiet {
		return 0
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 9
	}
	return 0
}
