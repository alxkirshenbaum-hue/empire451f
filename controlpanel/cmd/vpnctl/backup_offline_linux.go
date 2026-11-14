//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// This command authenticates off-node and checks a NEW private staging copy.
// Its report deliberately cannot promote a registry backup to verified.
func offlineVerify(args []string, out, stderr io.Writer) int {
	prepareParent := ""
	backupID := ""
	f := flag.NewFlagSet("backup offline-verify", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&prepareParent, "prepare-parent", "", "Create a NEW normalized database below this private recovery parent")
	f.StringVar(&backupID, "backup-id", "", "Authenticated backup receipt ID")
	envelope := f.String("envelope", "", "Encrypted envelope")
	private := f.String("private-key", "", "Off-node recipient key file")
	cipherHash := f.String("cipher-sha256", "", "Authenticated receipt digest")
	manifestHash := f.String("manifest-sha256", "", "Authenticated manifest digest")
	owner := f.String("owner-run", "", "Expected owner run")
	own := f.String("own-operation", "", "Captured backup operation")
	stage := f.String("staging", "", "New private output directory")
	helper := f.String("helper", "", "Trusted backup_artifact.py")
	panel := f.String("source-panel-root", "", "Trusted source panel root")
	state := f.String("source-state-root", "", "Trusted source state root")
	config := f.String("source-config-root", "", "Trusted source config root")
	wrapper:=f.String("source-wrapper","","Independently trusted exact wrapper path")
	wrapperSHA:=f.String("source-wrapper-sha256","","Independently pinned wrapper digest")
	if f.Parse(args) != nil || f.NArg() != 0 || !validCipherDigest(*cipherHash) || !validCipherDigest(*manifestHash) || !status.ValidID(*owner) || (*own != "" && !status.ValidID(*own)) || !filepath.IsAbs(*helper) || !filepath.IsAbs(*private) || !filepath.IsAbs(*envelope) || !filepath.IsAbs(*stage) || !(RestoreSourceRoots{PanelRoot:*panel,StateRoot:*state,ConfigRoot:*config,WrapperPath:*wrapper,WrapperSHA256:*wrapperSHA}).valid() {
		fmt.Fprintln(stderr, "Expected authenticated receipt, trusted source roots and private recovery paths")
		return 2
	}
	// A fresh private sibling keeps decrypted plaintext out of argv and reports.
	parent := filepath.Dir(*stage)
	resolved, e := filepath.EvalSymlinks(parent)
	i, se := os.Stat(parent)
	if e != nil || se != nil || resolved != parent || !i.IsDir() || i.Mode().Perm()&0077 != 0 || !trustedRecoveryParent(parent) {
		fmt.Fprintln(stderr, "Private recovery parent required")
		return 4
	}
	temp, e := os.MkdirTemp(parent, ".offline-decrypt-")
	if e != nil {
		return 4
	}
	defer os.RemoveAll(temp)
	plain := filepath.Join(temp, "archive.tar")
	if _, e = artifactCommand(context.Background(), *helper, map[string]string{"action": "decrypt", "envelope": *envelope, "private_key_path": *private, "output": plain, "expected_sha256": *cipherHash}); e != nil {
		fmt.Fprintln(stderr, "Envelope authentication failed")
		return 4
	}
	result, e := verifyManagedArchive(context.Background(), plain, *stage, *manifestHash, *owner, *own, RestoreSourceRoots{PanelRoot:*panel,StateRoot:*state,ConfigRoot:*config,WrapperPath:*wrapper,WrapperSHA256:*wrapperSHA})
	if e != nil {
		var stageError *archiveStageError; if errors.As(e, &stageError) { fmt.Fprintln(stderr, "Archive consistency verification failed:",stageError.Stage) } else { fmt.Fprintln(stderr, "Archive consistency verification failed") }
		return 4
	}
	var prepared string
	if prepareParent != "" {
		if !filepath.IsAbs(prepareParent) || !trustedRecoveryParent(prepareParent) || !status.ValidID(backupID) || !status.ValidID(*own) {
			fmt.Fprintln(stderr, "Explicit backup binding and trusted preparation parent required")
			return 2
		}
		keyPath := filepath.Join(*stage, strings.TrimPrefix(filepath.Join(*panel, "vault.key"), "/"))
		key, e := os.ReadFile(keyPath)
		if e != nil {
			return 4
		}
		v, e := vault.New(key)
		clear(key)
		if e != nil {
			return 4
		}
		source := filepath.Join(*stage, strings.TrimPrefix(filepath.Join(*panel, "state.db"), "/"))
		candidate, e := storage.PrepareRestoreCopy(context.Background(), source, prepareParent, v, storage.RestoreBinding{OwnerRun: *owner, OwnOperationID: *own, BackupID: backupID, CipherSHA256: *cipherHash, ManifestSHA256: *manifestHash})
		if e != nil {
			fmt.Fprintln(stderr, "Restore copy preparation failed")
			return 4
		}
		prepared = candidate.Path
	}
	report := struct {
		Outcome        string                     `json:"outcome"`
		ManifestSHA256 string                     `json:"manifest_sha256"`
		Inspection     storage.SnapshotInspection `json:"inspection"`
		PreparedCopy   string                     `json:"prepared_copy,omitempty"`
		UsableRestore  string                     `json:"usable_restore"`
	}{"artifact_check_passed", result.ManifestSHA256, result.Inspection, prepared, "not_run"}
	if json.NewEncoder(out).Encode(report) != nil {
		return 9
	}
	return 0
}

// Callers keep this recovery tree immutable throughout verification. Ancestors
// may be root-owned; a sticky shared ancestor cannot rename our owned child.
func trustedRecoveryParent(parent string) bool {
	for p := parent; ; p = filepath.Dir(p) {
		i, e := os.Lstat(p)
		if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
			return false
		}
		st, ok := i.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		if p == parent {
			if st.Uid != uint32(os.Geteuid()) || i.Mode().Perm()&0077 != 0 {
				return false
			}
		} else {
			if st.Uid != 0 && st.Uid != uint32(os.Geteuid()) {
				return false
			}
			if i.Mode().Perm()&0022 != 0 && i.Mode()&os.ModeSticky == 0 {
				return false
			}
		}
		if filepath.Dir(p) == p {
			return true
		}
	}
}
