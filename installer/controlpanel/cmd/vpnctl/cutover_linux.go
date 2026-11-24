//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
)

func cutoverLocal(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("migration cutover", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	installation := flags.String("installation", "", "Installation ID")
	run := flags.String("approved-plan", "", "Approved migration UUID")
	snapshot := flags.String("snapshot", "", "Protected original snapshot")
	stopped := flags.Bool("legacy-writers-stopped", false, "Operator confirms obsolete writer sessions are closed")
	reconcile := flags.Bool("reconcile", false, "Reinspect a previously blocked cutover")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !installationID.MatchString(*installation) || !status.ValidID(*run) || !filepath.IsAbs(*snapshot) || !*stopped {
		fmt.Fprintln(stderr, "Expected installation, approved plan, protected snapshot and stopped legacy writers")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Run as root on the entry")
		return 3
	}
	fail := func() int {
		fmt.Fprintln(stderr, "Cutover stopped; inspect protected migration state and use SSH reconciliation before further changes")
		return 5
	}
	policy, err := readWorkerPolicy(filepath.Join("/etc/vpn-control", "worker-"+*installation+".json"), *installation, *run)
	if err != nil {
		return fail()
	}
	directory := filepath.Dir(policy.Helper)
	helper := filepath.Join(directory, "handoff_legacy.py")
	templatePath := filepath.Join(directory, "vpn-add-user.template")
	for _, path := range []string{helper, templatePath, "/usr/local/bin/vpn-add-user"} {
		if err = rootFile(path, false); err != nil {
			return fail()
		}
	}
	state := filepath.Join("/var/lib/empire-vpn", *installation)
	base := filepath.Join("/etc/empire-vpn", *installation)
	template, err := os.ReadFile(templatePath)
	if err != nil {
		return fail()
	}
	for token, value := range map[string]string{"@STATE@": state, "@BASE@": base, "@PREFIX@": "evpn-" + *installation} {
		template = bytes.ReplaceAll(template, []byte(token), []byte(value))
	}
	writerMatches := func() error {
		actual, e := os.ReadFile("/usr/local/bin/vpn-add-user")
		if e != nil {
			return e
		}
		if !bytes.Equal(actual, template) {
			return caddy.ErrDrift
		}
		return nil
	}
	if writerMatches() != nil {
		return fail()
	}
	lock, err := installationLock("/run/lock/empire-vpn.lock")
	if err != nil {
		return fail()
	}
	defer lock.Close()
	ctx := context.Background()
	registry, err := openExistingRegistry(ctx, "/var/lib/vpn-control/state.db", "/var/lib/vpn-control/vault.key", 1)
	if err != nil {
		return fail()
	}
	defer registry.Close()
	info, err := os.Stat(state)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fail()
	}
	identity := info.Sys().(*syscall.Stat_t)
	ref := fmt.Sprintf("installation:%d:%d", identity.Dev, identity.Ino)
	runtime, err := caddy.NewUnixRuntime(policy.Socket, policy.Validate)
	if err != nil {
		return fail()
	}
	baseline := func(ctx context.Context) error {
		if e := writerMatches(); e != nil {
			return e
		}
		if _, e := verifyOwnedFiles(state, "/etc/empire-vpn", *run); e != nil {
			return e
		}
		return caddyBaseline(ctx, policy, runtime, filepath.Join(base, "Caddyfile"))
	}
	if receipt, e := registry.VerifiedCutoverReceipt(ctx, *run, ref); e == nil {
		if baseline(ctx) != nil {
			return fail()
		}
		if json.NewEncoder(out).Encode(receipt) != nil {
			return 9
		}
		return 0
	} else if !errors.Is(e, sql.ErrNoRows) {
		return fail()
	}
	args = []string{"-B", helper, "--snapshot", *snapshot, "--installation", *installation, "--staging-db", "/var/lib/vpn-control/state.db", "--approved-plan", *run, "--admin-socket", policy.Socket, "--wrapper-sha256", fmt.Sprintf("%x", sha256.Sum256(template)), "--lock-fd", "3"}
	if *reconcile {
		args = append(args, "--reconcile")
	}
	cmd := exec.CommandContext(ctx, "python3", args...)
	cmd.ExtraFiles = []*os.File{lock}
	if cmd.Run() != nil {
		return fail()
	}
	receipt, err := registry.CompleteLegacyCutover(ctx, *snapshot, *run, ref, commandProbe(policy.Probe), baseline)
	if err != nil {
		_ = registry.RequireCutoverReconciliation(ctx, *run, ref)
		return fail()
	}
	if json.NewEncoder(out).Encode(receipt) != nil {
		return 9
	}
	return 0
}
