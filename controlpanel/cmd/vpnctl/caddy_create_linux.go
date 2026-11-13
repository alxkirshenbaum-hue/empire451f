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
	checkpoint                              func(string)
	state, config, lock, panel, run, helper string
	runtime                                 caddy.Runtime
	probe                                   func(context.Context, string, vault.PlainSecret) error
	baseline                                func(context.Context) error
	mutationProbe                           func(context.Context, storage.AuthJob, vault.PlainSecret, vault.PlainSecret) error
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

func (w *createCaddyWorker) point(name string) {
	if w.checkpoint != nil {
		w.checkpoint(name)
	}
}

func (w *createCaddyWorker) directory(operation string) string {
	return filepath.Join(w.state, "panel-operations", operation)
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
	job, err := reg.OwnedAuthJob(ctx, w.run, intent.Operation)
	if err != nil {
		return empty, err
	}
	if job.Kind != "user.create" {
		return w.recoverMutation(ctx, reg, job, intent.Generation)
	}
	receipt, login, phase, err := reg.OwnedCreateState(ctx, w.run, intent.Operation)
	if err != nil {
		return empty, err
	}
	next, nextPhase, err := reg.NextOwnedAuth(ctx, w.run)
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
			w.point("after_global_lock")
			if w.baseline != nil {
				if err := w.baseline(ctx); err != nil {
					return storage.Receipt{}, err
				}
			}
			if recovered.OperationID != "" {
				return recovered, nil
			}
			if cleaned, err := w.cleanupCompleted(ctx, reg); err != nil || cleaned.OperationID != "" {
				return cleaned, err
			}
			receipt, phase, err := reg.NextOwnedAuth(ctx, w.run)
			if err != nil || phase == "" {
				return receipt, err
			}
			if phase != "queued" {
				err = reg.Transition(ctx, receipt.OperationID, phase, "reconcile_required")
				w.point("after_reconcile_required")
				return receipt, errors.Join(storage.ErrJournalConflict, err)
			}
			if !status.ValidID(receipt.OperationID) || !status.ValidID(receipt.UserID) {
				return receipt, caddy.ErrInput
			}
			job, err := reg.OwnedAuthJob(ctx, w.run, receipt.OperationID)
			if err != nil {
				return receipt, err
			}
			if job.Kind != "user.create" {
				return receipt, w.applyMutation(ctx, reg, job)
			}
			generation, err := verifyOwnedFiles(w.state, w.config, w.run)
			if err != nil {
				return receipt, err
			}
			w.point("after_observed_preflight")
			for _, dir := range []string{filepath.Join(w.state, "panel-operations"), w.directory(receipt.OperationID)} {
				if err = os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
					return receipt, err
				}
				info, e := os.Lstat(dir)
				if e != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
					return receipt, caddy.ErrInput
				}
			}
			err = reg.ApplyCreate(ctx, receipt, func(ctx context.Context, login string, secret vault.PlainSecret) error {
				w.point("after_running_commit")
				p, e := caddy.PrepareAuthObserved(ctx, w.runtime, w.directory(receipt.OperationID), receipt.OperationID, generation, caddy.AuthChange{Login: login, Password: string(secret)}, w.point)
				if e != nil {
					return e
				}
				defer p.Clear()
				base := filepath.Join(w.config, filepath.Base(w.state))
				if e = w.files(ctx, "prepare", receipt, generation, map[string]any{"auth": filepath.Join(base, "auth.caddy"), "caddyfile": filepath.Join(base, "Caddyfile"), "prepared_dir": w.directory(receipt.OperationID), "login": login, "password": string(secret)}); e != nil {
					return e
				}
				w.point("after_prepared_fsync")
				if e = p.ApplyObserved(ctx, w.runtime, func(ctx context.Context) error { return w.probe(ctx, login, secret) }, w.point); e != nil {
					return e
				}
				return w.files(ctx, "publish_files", receipt, generation, nil)
			})
			if err != nil {
				w.point("after_reconcile_required")
				return receipt, err
			}
			w.point("after_verified_db_commit")
			return receipt, w.finish(ctx, receipt, generation)
		})
}

func (w *createCaddyWorker) finish(ctx context.Context, receipt storage.Receipt, generation int64) error {
	if err := w.files(ctx, "finish", receipt, generation, map[string]any{"registry": filepath.Join(w.panel, "state.db")}); err != nil {
		return err
	}
	if err := w.removePrepared(receipt.OperationID); err != nil {
		return err
	}
	w.point("after_staging_cleanup")
	return nil
}

// A crash after helper.finish may leave only the private Caddy snapshot. Clean
// only a known succeeded job; no recursive removal or configuration mutation.
func (w *createCaddyWorker) cleanupCompleted(ctx context.Context, reg *storage.Registry) (storage.Receipt, error) {
	var empty storage.Receipt
	entries, err := os.ReadDir(filepath.Join(w.state, "panel-operations"))
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
		job, e := reg.OwnedAuthJob(ctx, w.run, entry.Name())
		receipt, phase := job.Receipt, job.Phase
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

// mutationChange derives both sides from durable intent; retries never invent a
// credential. Disabled -> deleted is an absence assertion.
func mutationChange(j storage.AuthJob, login string, old, fresh vault.PlainSecret) caddy.AuthChange {
	change := caddy.AuthChange{Login: login}
	if j.BeforeStatus == "active" {
		change.Previous = string(old)
	}
	if j.AfterStatus == "active" {
		change.Password = string(fresh)
	}
	return change
}

func (w *createCaddyWorker) applyMutation(ctx context.Context, reg *storage.Registry, j storage.AuthJob) error {
	if w.mutationProbe == nil {
		return caddy.ErrInput
	}
	generation, err := verifyOwnedFiles(w.state, w.config, w.run)
	if err != nil {
		return err
	}
	w.point("after_observed_preflight")
	if err = reg.Transition(ctx, j.OperationID, "queued", "running"); err != nil {
		return err
	}
	w.point("after_running_commit")
	for _, dir := range []string{filepath.Join(w.state, "panel-operations"), w.directory(j.OperationID)} {
		if err = os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
			result := errors.Join(err, reg.Transition(ctx, j.OperationID, "running", "reconcile_required"))
			w.point("after_reconcile_required")
			return result
		}
	}
	err = reg.WithMutationSecrets(ctx, j, func(login string, old, fresh vault.PlainSecret) error {
		change := mutationChange(j, login, old, fresh)
		p, e := caddy.PrepareAuthObserved(ctx, w.runtime, w.directory(j.OperationID), j.OperationID, generation, change, w.point)
		if e != nil {
			return e
		}
		defer p.Clear()
		base := filepath.Join(w.config, filepath.Base(w.state))
		if e = w.files(ctx, "prepare", j.Receipt, generation, map[string]any{"auth": filepath.Join(base, "auth.caddy"), "caddyfile": filepath.Join(base, "Caddyfile"), "prepared_dir": w.directory(j.OperationID), "login": login, "password": change.Password, "previous": change.Previous}); e != nil {
			return e
		}
		w.point("after_prepared_fsync")
		if e = p.ApplyObserved(ctx, w.runtime, func(ctx context.Context) error { return w.mutationProbe(ctx, j, old, fresh) }, w.point); e != nil {
			return e
		}
		return w.files(ctx, "publish_files", j.Receipt, generation, nil)
	})
	if err != nil {
		result := errors.Join(err, reg.Transition(ctx, j.OperationID, "running", "reconcile_required"))
		w.point("after_reconcile_required")
		return result
	}
	if err = reg.Transition(ctx, j.OperationID, "running", "verifying"); err != nil {
		return err
	}
	if err = reg.CompleteVerifiedMutation(ctx, w.run, j); err != nil {
		return err
	}
	w.point("after_verified_db_commit")
	return w.finish(ctx, j.Receipt, generation)
}

func (w *createCaddyWorker) recoverMutation(ctx context.Context, reg *storage.Registry, j storage.AuthJob, generation int64) (storage.Receipt, error) {
	fail := func(e error) (storage.Receipt, error) {
		if j.Phase == "running" || j.Phase == "verifying" {
			e = errors.Join(e, reg.Transition(ctx, j.OperationID, j.Phase, "reconcile_required"))
		}
		return j.Receipt, e
	}
	if w.mutationProbe == nil {
		return fail(caddy.ErrInput)
	}
	next, phase, err := reg.NextOwnedAuth(ctx, w.run)
	if err != nil {
		return fail(err)
	}
	if j.Phase != "succeeded" && next != j.Receipt || j.Phase == "succeeded" && (phase == "running" || phase == "verifying") {
		return fail(storage.ErrJournalConflict)
	}
	if err = w.files(ctx, "inspect", j.Receipt, generation, nil); err != nil {
		return fail(err)
	}
	p, err := caddy.ReadPrepared(w.directory(j.OperationID), j.OperationID, generation)
	if err != nil {
		return fail(err)
	}
	defer p.Clear()
	err = reg.WithMutationSecrets(ctx, j, func(login string, old, fresh vault.PlainSecret) error {
		candidate, e := caddy.PatchAuth(p.Before, mutationChange(j, login, old, fresh))
		if e != nil {
			return e
		}
		defer clear(candidate)
		if !caddy.ConfigEqual(candidate, p.Candidate) {
			return caddy.ErrDrift
		}
		if e = p.Verify(ctx, w.runtime, func(ctx context.Context) error { return w.mutationProbe(ctx, j, old, fresh) }); e != nil {
			return e
		}
		return w.files(ctx, "publish_files", j.Receipt, generation, nil)
	})
	if err != nil {
		return fail(err)
	}
	if j.Phase != "succeeded" {
		if j.Phase == "running" {
			if err = reg.Transition(ctx, j.OperationID, "running", "verifying"); err != nil {
				return j.Receipt, err
			}
		}
		if err = reg.CompleteVerifiedMutation(ctx, w.run, j); err != nil {
			return j.Receipt, err
		}
	}
	return j.Receipt, w.finish(ctx, j.Receipt, generation)
}
