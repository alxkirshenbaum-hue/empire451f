package main

import (
	"context"
	"encoding/json"
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
	if flags.Parse(args) != nil || flags.NArg() != 0 || !status.ValidID(*run) || *db == "" || *snapshot == "" || *keyPath == "" || *version < 1 {
		fmt.Fprintln(stderr, "Usage: vpnctl migration execute --approved-plan UUID --staging-db FILE --snapshot DIR --vault-key-file FILE [--key-version N]")
		return 2
	}
	info, err := os.Lstat(*db)
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
		fmt.Fprintln(stderr, "Existing staging registry required")
		return 2
	}
	info, err = os.Lstat(*keyPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		fmt.Fprintln(stderr, "Private 32-byte vault key file required")
		return 3
	}
	key, err := os.ReadFile(*keyPath)
	if err != nil {
		return 3
	}
	cipher, err := vault.New(key)
	clear(key)
	if err != nil {
		return 3
	}
	ctx := context.Background()
	registry, err := storage.Open(ctx, *db, cipher, *version)
	if err != nil {
		fmt.Fprintln(stderr, "Cannot open staging registry with supplied key")
		return 3
	}
	defer registry.Close()
	receipt, err := registry.StageLegacy(ctx, *snapshot, *run)
	if err != nil {
		fmt.Fprintln(stderr, "Staging refused; check the plan, snapshot and registry")
		return 1
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 9
	}
	return 0
}
