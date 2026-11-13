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

var errRegistryFile = errors.New("existing private registry required")

func openExistingRegistry(ctx context.Context, db, keyPath string, version int64) (*storage.Registry, error) {
	info, err := os.Lstat(db)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		return nil, errRegistryFile
	}
	info, err = os.Lstat(keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return nil, storage.ErrVaultKey
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, storage.ErrVaultKey
	}
	defer clear(key)
	cipher, err := vault.New(key)
	if err != nil {
		return nil, storage.ErrVaultKey
	}
	return storage.Open(ctx, db, cipher, version)
}

func executeMigration(action string, args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("migration "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	run := flags.String("approved-plan", "", "Approved plan UUID")
	db := flags.String("staging-db", "", "Existing private staging registry")
	var directory string
	if action == "reverse-export" {
		flags.StringVar(&directory, "output-dir", "", "Existing private output directory")
	} else {
		flags.StringVar(&directory, "snapshot", "", "Offline snapshot directory")
	}
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
	if flags.Parse(args) != nil || flags.NArg() != 0 || !status.ValidID(*run) || *db == "" || directory == "" || *keyPath == "" || *version < 1 || (*quiet && *machine) {
		return fail(2, "VALIDATION_ERROR", "Expected an approved plan UUID, staging DB, directory and key file")
	}
	ctx := context.Background()
	registry, err := openExistingRegistry(ctx, *db, *keyPath, *version)
	if err != nil {
		if errors.Is(err, errRegistryFile) {
			return fail(2, "VALIDATION_ERROR", "Existing staging registry required")
		}
		if errors.Is(err, storage.ErrVaultKey) {
			return fail(5, "SECRET_UNAVAILABLE", "Vault key verification failed")
		}
		return fail(5, "DEPENDENCY_UNAVAILABLE", "Cannot open staging registry")
	}
	defer registry.Close()
	if action == "reverse-export" {
		err = registry.ExportLegacy(ctx, *run, directory)
		switch {
		case errors.Is(err, storage.ErrLegacyConflict):
			return fail(4, "VERSION_CONFLICT", "Registry is not ready for reverse export")
		case errors.Is(err, os.ErrExist):
			return fail(4, "ALREADY_EXISTS", "Output already exists")
		case err != nil:
			return fail(9, "EXPORT_FAILED", "Could not export active credentials")
		}
		if !*quiet {
			if _, err = fmt.Fprintln(out, `{"status":"exported"}`); err != nil {
				return 9
			}
		}
		return 0
	}
	receipt, err := registry.StageLegacy(ctx, directory, *run)
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
