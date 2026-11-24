//go:build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
)

func mutateLocalUser(action string, args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("user "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	installation := flags.String("installation", "", "Installation ID")
	run := flags.String("owner-run", "", "Approved writer run")
	user := flags.String("user", "", "User UUID")
	key := flags.String("idempotency-key", "", "Stable request key")
	version := flags.Int64("expected-version", 0, "Expected user revision")
	reason := flags.String("reason", "", "Reason for the change")
	confirm := flags.Bool("confirm-delete", false, "Confirm permanent tombstone")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !installationID.MatchString(*installation) || !status.ValidID(*run) || !status.ValidID(*user) || !status.ValidID(*key) || *version < 1 {
		fmt.Fprintln(stderr, "Expected installation, owner run, user UUID, idempotency key and expected version")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Run as root on the entry")
		return 3
	}
	fmt.Fprintln(stderr, caddy.ApplyNotice)
	req := storage.MutationRequest{UserID: *user, Action: action, ExpectedVersion: *version, Reason: *reason, ConfirmDelete: *confirm}
	rec, err := withOwnedInstallation(filepath.Join("/var/lib/empire-vpn", *installation), "/etc/empire-vpn", "/run/lock/empire-vpn.lock", "/var/lib/vpn-control", *run, func(ctx context.Context, r *storage.Registry) (storage.Receipt, error) {
		return r.QueueOwnedMutation(ctx, *run, "ssh-root", *key, req)
	})
	if err != nil {
		fmt.Fprintln(stderr, "Cannot queue user change; inspect ownership, version, protection and operation status")
		return 4
	}
	fmt.Fprintf(out, "User change operation: %s\n", rec.OperationID)
	return 0
}
