//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

type createCaddyWorker struct {
	state, config, lock, panel, run, helper string
	runtime                                 caddy.Runtime
	probe                                   func(context.Context, string, vault.PlainSecret) error
}

// Helper requests are root-owned deployment policy; secrets travel only on stdin.
func (w *createCaddyWorker) files(ctx context.Context, action string, receipt storage.Receipt, generation int64, extra map[string]any) error {
	request := map[string]any{"action": action, "state": w.state, "operation": receipt.OperationID, "run": w.run, "generation": generation}
	for k, v := range extra {
		request[k] = v
	}
	data, err := json.Marshal(request)
	if err != nil {
		return caddy.ErrInput
	}
	defer clear(data)
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-B", w.helper)
	cmd.Stdin = bytes.NewReader(data)
	if cmd.Run() != nil {
		return errors.New("protected auth file operation failed")
	}
	return nil
}

func (w *createCaddyWorker) directory(operation string) string {
	return filepath.Join(w.panel, "operations", operation)
}

func (w *createCaddyWorker) recover(ctx context.Context, reg *storage.Registry) (storage.Receipt, error) {
	var empty storage.Receipt
	path := filepath.Join(w.state, "panel-auth-pending.json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return empty, caddy.ErrInput
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return empty, err
	}
	defer clear(data)
	var intent struct {
		Operation, Run, Prepared string
		Generation               int64
	}
	if json.Unmarshal(data, &intent) != nil || intent.Run != w.run || !status.ValidID(intent.Operation) || intent.Prepared != filepath.Join(w.directory(intent.Operation), "prepared.json") {
		return empty, caddy.ErrInput
	}
	receipt, login, phase, err := reg.OwnedCreateState(ctx, w.run, intent.Operation)
	if err != nil {
		return empty, err
	}
	next, nextPhase, err := reg.NextOwnedCreate(ctx, w.run)
	if err != nil {
		return empty, err
	}
	if phase != "succeeded" && next != receipt || phase == "succeeded" && (nextPhase == "running" || nextPhase == "verifying") {
		return empty, storage.ErrJournalConflict
	}
	if err = w.files(ctx, "inspect", receipt, intent.Generation, nil); err != nil {
		return empty, err
	}
	p, err := caddy.ReadPrepared(w.directory(receipt.OperationID), receipt.OperationID, intent.Generation)
	if err != nil {
		return empty, err
	}
	defer p.Clear()
	verify := func(ctx context.Context, login string, secret vault.PlainSecret) error {
		candidate, e := caddy.PatchCreate(p.Before, login, string(secret))
		if e != nil {
			return e
		}
		defer clear(candidate)
		if !bytes.Equal(candidate, p.Candidate) {
			return caddy.ErrDrift
		}
		if e = p.Verify(ctx, w.runtime, func(ctx context.Context) error { return w.probe(ctx, login, secret) }); e != nil {
			return e
		}
		return w.files(ctx, "publish_files", receipt, p.Generation, nil)
	}
	if phase == "succeeded" {
		secret, e := reg.OpenForPurpose(ctx, receipt.UserID, storage.PrepareAuth)
		if e != nil {
			return empty, e
		}
		err = verify(ctx, login, secret)
		clear(secret)
	} else {
		err = reg.RecoverCreate(ctx, receipt, verify)
	}
	if err != nil {
		return empty, err
	}
	return receipt, w.finish(ctx, receipt, p.Generation)
}

// One job per invocation, including recovery/cleanup of an already committed
// job. No normal drift check is bypassed: exact journal proof precedes repair,
// and the ordinary manifest/hash preflight runs again after it.
func (w *createCaddyWorker) once() (storage.Receipt, error) {
	var recovered storage.Receipt
	if w.runtime == nil || w.probe == nil {
		return recovered, caddy.ErrInput
	}
	return withOwnedInstallationRecovery(w.state, w.config, w.lock, w.panel, w.run,
		func(ctx context.Context, reg *storage.Registry) error {
			var err error
			recovered, err = w.recover(ctx, reg)
			return err
		},
		func(ctx context.Context, reg *storage.Registry) (storage.Receipt, error) {
			if recovered.OperationID != "" {
				return recovered, nil
			}
			if cleaned, err := w.cleanupCompleted(ctx, reg); err != nil || cleaned.OperationID != "" {
				return cleaned, err
			}
			receipt, phase, err := reg.NextOwnedCreate(ctx, w.run)
			if err != nil || phase == "" {
				return receipt, err
			}
			if phase != "queued" {
				return receipt, storage.ErrJournalConflict
			}
			generation, err := verifyOwnedFiles(w.state, w.config, w.run)
			if err != nil {
				return receipt, err
			}
			for _, dir := range []string{filepath.Join(w.panel, "operations"), w.directory(receipt.OperationID)} {
				if err = os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
					return receipt, err
				}
				info, e := os.Lstat(dir)
				if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
					return receipt, caddy.ErrInput
				}
			}
			err = reg.ApplyCreate(ctx, receipt, func(ctx context.Context, login string, secret vault.PlainSecret) error {
				p, e := caddy.Prepare(ctx, w.runtime, w.directory(receipt.OperationID), receipt.OperationID, generation, login, string(secret))
				if e != nil {
					return e
				}
				defer p.Clear()
				base := filepath.Join(w.config, filepath.Base(w.state))
				if e = w.files(ctx, "prepare", receipt, generation, map[string]any{"auth": filepath.Join(base, "auth.caddy"), "caddyfile": filepath.Join(base, "Caddyfile"), "prepared_dir": w.directory(receipt.OperationID), "login": login, "password": string(secret)}); e != nil {
					return e
				}
				if e = p.Apply(ctx, w.runtime, func(ctx context.Context) error { return w.probe(ctx, login, secret) }); e != nil {
					return e
				}
				return w.files(ctx, "publish_files", receipt, generation, nil)
			})
			if err != nil {
				return receipt, err
			}
			return receipt, w.finish(ctx, receipt, generation)
		})
}

func (w *createCaddyWorker) finish(ctx context.Context, receipt storage.Receipt, generation int64) error {
	if err := w.files(ctx, "finish", receipt, generation, map[string]any{"registry": filepath.Join(w.panel, "state.db")}); err != nil {
		return err
	}
	return w.removePrepared(receipt.OperationID)
}

// A crash after helper.finish may leave only the private Caddy snapshot. Clean
// only a known succeeded job; no recursive removal or configuration mutation.
func (w *createCaddyWorker) cleanupCompleted(ctx context.Context, reg *storage.Registry) (storage.Receipt, error) {
	var empty storage.Receipt
	entries, err := os.ReadDir(filepath.Join(w.panel, "operations"))
	if errors.Is(err, os.ErrNotExist) {
		return empty, nil
	}
	if err != nil {
		return empty, err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !status.ValidID(entry.Name()) {
			return empty, caddy.ErrInput
		}
		receipt, _, phase, e := reg.OwnedCreateState(ctx, w.run, entry.Name())
		if e != nil || phase != "succeeded" {
			continue
		}
		return receipt, w.removePrepared(receipt.OperationID)
	}
	return empty, nil
}

func (w *createCaddyWorker) removePrepared(operation string) error {
	dir := w.directory(operation)
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return caddy.ErrInput
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) > 1 || len(entries) == 1 && entries[0].Name() != "prepared.json" {
		return caddy.ErrInput
	}
	if len(entries) == 1 {
		path := filepath.Join(dir, "prepared.json")
		info, err = os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
			return caddy.ErrInput
		}
		if err = os.Remove(path); err != nil {
			return err
		}
	}
	if err = os.Remove(dir); err != nil {
		return err
	}
	parent, err := os.Open(filepath.Dir(dir))
	if err != nil {
		return err
	}
	return errors.Join(parent.Sync(), parent.Close())
}
