//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// portableInstallationHash binds the reviewed destination beforeimage without
// exposing auth, key, policy or configuration contents in the public plan.
func portableInstallationHash(installation string) (string, error) {
	h := sha256.New()
	paths := []string{filepath.Join("/var/lib/empire-vpn", installation, "manifest.json"), filepath.Join("/etc/empire-vpn", installation, "auth.caddy"), filepath.Join("/etc/empire-vpn", installation, "Caddyfile"), "/var/lib/vpn-control/vault.key", filepath.Join("/etc/vpn-control", "worker-"+installation+".json")}
	for _, path := range paths {
		if e := rootFile(path, false); e != nil {
			return "", e
		}
		f, e := os.Open(path)
		if e != nil {
			return "", e
		}
		st, e := f.Stat()
		if e != nil {
			f.Close()
			return "", e
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || !st.Mode().IsRegular() || st.Size() > storage.SnapshotMaxBytes {
			f.Close()
			return "", storage.ErrSnapshotState
		}
		fmt.Fprintf(h, "%s\x00%d:%d:%d:%d:%d:%d\x00", path, sys.Dev, sys.Ino, sys.Uid, sys.Gid, st.Mode().Perm(), st.Size())
		n, e := io.Copy(h, io.LimitReader(f, storage.SnapshotMaxBytes+1))
		ce := f.Close()
		if e != nil {
			return "", e
		}
		if ce != nil {
			return "", ce
		}
		if n != st.Size() {
			return "", storage.ErrSnapshotState
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func portableCommand(action string, args []string, out, stderr io.Writer) int {
	f := flag.NewFlagSet("portable "+action, flag.ContinueOnError)
	f.SetOutput(io.Discard)
	installation := f.String("installation", "", "Clean destination installation")
	source := f.String("source-db", "", "Authenticated private offline source snapshot")
	keyPath := f.String("source-key", "", "Private staged source vault key (not RSA recipient key)")
	owner := f.String("source-owner-run", "", "Source receipt owner UUID")
	own := f.String("source-operation", "", "Source captured backup UUID")
	run := f.String("destination-run", "", "New destination writer UUID; retain for retry")
	expected := f.String("plan-sha256", "", "Approved preview plan digest")
	baseline := f.String("expected-installation-sha256", "", "Approved installation beforeimage digest")
	replace := f.Bool("replace-initial-catalog", false, "Explicitly approve replacing pristine bootstrap catalog/auth")
	resume := f.Bool("resume", false, "Reconcile only the exact persisted portable import")
	if f.Parse(args) != nil || f.NArg() != 0 || !installationID.MatchString(*installation) || !status.ValidID(*owner) || !status.ValidID(*run) || (*own != "" && !status.ValidID(*own)) || !filepath.IsAbs(*source) || !filepath.IsAbs(*keyPath) || (action != "preview" && action != "import") {
		fmt.Fprintln(stderr, "Expected clean installation, private authenticated source and writer UUIDs")
		return 2
	}
	if action == "import" && (!validCipherDigest(*expected) || !validCipherDigest(*baseline) || !*replace) {
		fmt.Fprintln(stderr, "Import requires approved plan, installation digest and explicit bootstrap replacement")
		return 2
	}
	if action == "preview" && (*resume || *replace || *expected != "" || *baseline != "") {
		fmt.Fprintln(stderr, "Preview does not accept import approval options")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Run on the protected first-start staging host as root")
		return 3
	}
	if !trustedRecoveryParent(filepath.Dir(*source)) || !trustedRecoveryParent(filepath.Dir(*keyPath)) || rootFile(*source, false) != nil || rootFile(*keyPath, false) != nil {
		fmt.Fprintln(stderr, "Private immutable authenticated source staging required")
		return 4
	}
	info, e := os.Stat(*keyPath)
	if e != nil || info.Size() != 32 || info.Mode().Perm()&0077 != 0 {
		return 4
	}
	key, e := os.ReadFile(*keyPath)
	if e != nil {
		return 4
	}
	v, e := vault.New(key)
	clear(key)
	if e != nil {
		return 4
	}
	lock, e := installationLock("/run/lock/empire-vpn.lock")
	if e != nil {
		return 4
	}
	defer lock.Close()
	ctx := context.Background()
	r, e := openExistingRegistry(ctx, "/var/lib/vpn-control/state.db", "/var/lib/vpn-control/vault.key", 1)
	if e != nil {
		fmt.Fprintln(stderr, "Fresh destination registry unavailable")
		return 4
	}
	defer r.Close()
	p, e := readWorkerPolicy(filepath.Join("/etc/vpn-control", "worker-"+*installation+".json"), *installation, *run)
	if e != nil {
		fmt.Fprintln(stderr, "Root-controlled destination worker policy unavailable")
		return 4
	}
	observed, e := portableInstallationHash(*installation)
	if e != nil {
		return 4
	}
	if action == "preview" {
		plan, e := r.PreviewPortable(ctx, *source, v, *owner, *own)
		if e != nil {
			fmt.Fprintln(stderr, "Portable preview refused: source or destination conflict")
			return 4
		}
		return portableJSON(out, map[string]any{"plan_sha256": plan.Hash, "installation_sha256": observed, "users": plan.Users, "users_preview": plan.UsersPreview, "destination_run": *run, "replace_initial_template_catalog": plan.ReplaceInitialCatalog, "activation": "not_started"})
	}
	if !*resume {
		if e = portableSpace(*source); e != nil {
			fmt.Fprintln(stderr, "Insufficient free space for portable import staging and WAL")
			return 4
		}
	}
	if !*resume && observed != *baseline {
		fmt.Fprintln(stderr, "Destination changed since preview")
		return 4
	}
	receipt, e := applyPortableImport(ctx, *installation, p, r, *source, v, *owner, *own, *run, *expected, *baseline, *replace, *resume)
	if e != nil {
		fmt.Fprintln(stderr, "Portable import stopped; preserve the plan and use exact --resume after inspection")
		return 5
	}
	return portableJSON(out, map[string]any{"operation_id": receipt.OperationID, "users": receipt.Users, "destination_run": *run, "status": "verified_cutover"})
}
func portableJSON(out io.Writer, value any) int {
	if json.NewEncoder(out).Encode(value) != nil {
		return 9
	}
	return 0
}

// Reserve a conservative bounded DB/WAL working peak on the actual destination
// filesystem. This is operation safety, not a fixed overall disk/RAM gate.
func portableSpace(source string) error {
	i, e := os.Stat(source)
	if e != nil {
		return e
	}
	if i.Size() < 1 || i.Size() > storage.SnapshotMaxBytes {
		return storage.ErrSnapshotState
	}
	needed := uint64(i.Size())*3 + 16*1024*1024
	for _, path := range []string{"/var/lib/vpn-control", "/var/lib/empire-vpn", "/etc/empire-vpn"} {
		var st syscall.Statfs_t
		if e = syscall.Statfs(path, &st); e != nil {
			return e
		}
		if uint64(st.Bsize) == 0 || st.Bavail < needed/uint64(st.Bsize)+1 {
			return storage.ErrSnapshotState
		}
	}
	return nil
}
