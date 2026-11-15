//go:build linux

package main

import (
	"context"
	"database/sql"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"os"
	"path/filepath"
)

// Caller owns the single existing installation lock for this entire saga.
func applyPortableImport(ctx context.Context, installation string, policy workerPolicy, r *storage.Registry, source string, key *vault.Vault, owner, own, run, plan, baseline string, replace, resume bool) (storage.LegacyReceipt, error) {
	receipt, phase, e := r.PortableCutoverState(ctx, run, plan, baseline)
	if errors.Is(e, sql.ErrNoRows) {
		if !resume {
			if _, e = r.ImportPortable(ctx, source, key, owner, own, plan, replace); e != nil {
				return receipt, e
			}
		}
		receipt, e = r.BeginPortableCutover(ctx, run, plan, baseline)
		phase = "running"
	}
	if e != nil {
		return receipt, e
	}
	if phase != "running" && phase != "succeeded" {
		return receipt, storage.ErrLegacyConflict
	}
	state := filepath.Join("/var/lib/empire-vpn", installation)
	base := filepath.Join("/etc/empire-vpn", installation)
	rt, e := caddy.NewUnixRuntime(policy.Socket, policy.Validate)
	if e != nil {
		return receipt, e
	}
	w := &createCaddyWorker{state: state, config: "/etc/empire-vpn", panel: "/var/lib/vpn-control", run: run, helper: policy.Helper, runtime: rt}
	directory := w.directory(receipt.OperationID)
	if e = os.MkdirAll(filepath.Dir(directory), 0700); e != nil {
		return receipt, e
	}
	credentials, e := r.PortableCredentials(ctx)
	if e != nil {
		return receipt, e
	}
	defer func() {
		for _, x := range credentials {
			clear(x.Secret)
		}
	}()
	var active []caddy.AuthCredential
	var users []map[string]string
	for _, x := range credentials {
		if x.Status == "active" {
			active = append(active, caddy.AuthCredential{Login: x.Login, Password: string(x.Secret)})
			users = append(users, map[string]string{"username": x.Login, "password": string(x.Secret)})
		}
	}
	p, e := caddy.ReadPrepared(directory, receipt.OperationID, 1)
	if errors.Is(e, os.ErrNotExist) {
		if phase == "succeeded" {
			return receipt, storage.ErrLegacyDrift
		}
		p, e = caddy.PreparePortableAuth(ctx, rt, directory, receipt.OperationID, 1, active)
	}
	if e != nil {
		return receipt, e
	}
	defer p.Clear()
	if _, e = os.Lstat(filepath.Join(state, "panel-auth-pending.json")); errors.Is(e, os.ErrNotExist) {
		if phase == "succeeded" {
			_, e = verifyOwnedFiles(state, "/etc/empire-vpn", run)
			if e != nil {
				return receipt, e
			}
			e = p.Verify(ctx, rt, func(context.Context) error { return nil })
			if e != nil {
				return receipt, e
			}
			return receipt, w.removePrepared(receipt.OperationID)
		}
		observed, err := portableInstallationHash(installation)
		if err != nil || observed != baseline {
			return receipt, storage.ErrLegacyDrift
		}
		e = w.files(ctx, "prepare_portable", storage.Receipt{OperationID: receipt.OperationID}, 1, map[string]any{"auth": filepath.Join(base, "auth.caddy"), "caddyfile": filepath.Join(base, "Caddyfile"), "prepared_dir": directory, "registry": "/var/lib/vpn-control/state.db", "users": users, "installation_hash": baseline})
	} else if e == nil {
		e = w.files(ctx, "inspect", storage.Receipt{OperationID: receipt.OperationID}, 1, nil)
	}
	if e != nil {
		return receipt, e
	}
	if phase == "running" {
		// Known live before/candidate only; an uncertain load is never blindly retried.
		e = p.Verify(ctx, rt, func(context.Context) error { return nil })
		if e != nil {
			e = p.Apply(ctx, rt, func(context.Context) error { return nil })
		}
		if e != nil {
			return receipt, e
		}
		if e = w.files(ctx, "publish_files", storage.Receipt{OperationID: receipt.OperationID}, 1, nil); e != nil {
			return receipt, e
		}
		probe := commandMutationProbe(policy.Probe)
		receipt, e = r.CompletePortableCutover(ctx, run, func(ctx context.Context, login string, secret vault.PlainSecret, active bool) error {
			status := "disabled"
			if active {
				status = "active"
			}
			return probe(ctx, storage.AuthJob{Login: login, AfterStatus: status}, secret, secret)
		}, func(ctx context.Context) error {
			return p.Verify(ctx, rt, func(ctx context.Context) error {
				return w.files(ctx, "inspect", storage.Receipt{OperationID: receipt.OperationID}, 1, nil)
			})
		})
		if e != nil {
			return receipt, e
		}
	}
	e = w.finish(ctx, storage.Receipt{OperationID: receipt.OperationID}, 1)
	return receipt, e
}
