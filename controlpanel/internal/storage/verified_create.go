package storage

import (
	"context"
	"database/sql"
	"errors"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// RecoverCreate is verify-only: it never reapplies Caddy or generates a secret.
// The caller holds the installation lock and checks owner, generation and the
// durable candidate against the observed configuration before calling this.
// An ambiguous result stays blocked for an explicit recovery decision.
func (r *Registry) RecoverCreate(ctx context.Context, receipt Receipt, verify func(context.Context, string, vault.PlainSecret) error) error {
	if verify == nil {
		return ErrInvalidMetadata
	}
	var login, phase string
	var version int64
	err := r.db.QueryRowContext(ctx, `SELECT u.login,u.row_version,o.status FROM operations o JOIN users u ON o.target_id=u.id
 WHERE o.id=? AND u.id=? AND o.kind='user.create' AND o.target_type='user'
 AND o.status IN ('running','verifying') AND u.status='provisioning' AND u.protected=0`, receipt.OperationID, receipt.UserID).Scan(&login, &version, &phase)
	if err != nil {
		return err
	}
	secret, err := r.OpenForPurpose(ctx, receipt.UserID, PrepareAuth)
	if err != nil {
		return err
	}
	defer clear(secret)
	if err = verify(ctx, login, secret); err != nil {
		return errors.Join(err, r.Transition(ctx, receipt.OperationID, phase, "reconcile_required"))
	}
	if phase == "running" {
		if err = r.Transition(ctx, receipt.OperationID, phase, "verifying"); err != nil {
			return err
		}
	}
	return r.CompleteVerifiedCreate(ctx, receipt, version)
}

// NextOwnedCreate is called under the installation lock after filesystem drift
// checks. Never skip unresolved work to start another configuration mutation.
func (r *Registry) NextOwnedCreate(ctx context.Context, run string) (Receipt, string, error) {
	var receipt Receipt
	var phase string
	if err := requireVerifiedCutover(ctx, r.db, run); err != nil {
		return receipt, phase, err
	}
	// The registry is scoped to one installation. Any uncertain operation blocks
	// the queue, including operations of a kind this worker cannot recover.
	var blocked int
	if err := r.db.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE status IN ('reconcile_required','rollback_running')
 OR (status IN ('running','verifying') AND kind!='user.create')`).Scan(&blocked); err != nil {
		return receipt, phase, err
	}
	if blocked != 0 {
		return receipt, phase, ErrJournalConflict
	}
	err := r.db.QueryRowContext(ctx, `SELECT id,target_id,status FROM operations WHERE kind='user.create' AND target_type='user'
 AND status IN ('queued','running','verifying') ORDER BY CASE WHEN status='queued' THEN 1 ELSE 0 END,created_at,id LIMIT 1`).Scan(&receipt.OperationID, &receipt.UserID, &phase)
	if errors.Is(err, sql.ErrNoRows) {
		return receipt, "", nil
	}
	return receipt, phase, err
}

// ApplyCreate runs under the writer's installation lock. The adapter returns
// success only after applying the candidate and checking fresh connections.
func (r *Registry) ApplyCreate(ctx context.Context, receipt Receipt, applyAndVerify func(context.Context, string, vault.PlainSecret) error) error {
	if applyAndVerify == nil {
		return ErrInvalidMetadata
	}
	var login string
	var version int64
	err := r.db.QueryRowContext(ctx, `SELECT u.login,u.row_version FROM operations o JOIN users u ON o.target_id=u.id
 WHERE o.id=? AND u.id=? AND o.kind='user.create' AND o.target_type='user' AND o.status='queued'
 AND u.status='provisioning' AND u.protected=0`, receipt.OperationID, receipt.UserID).Scan(&login, &version)
	if err != nil {
		return err
	}
	if err = r.Transition(ctx, receipt.OperationID, "queued", "running"); err != nil {
		return err
	}
	secret, err := r.OpenForPurpose(ctx, receipt.UserID, PrepareAuth)
	if err != nil {
		return errors.Join(err, r.Transition(ctx, receipt.OperationID, "running", "failed"))
	}
	defer clear(secret)
	if err = applyAndVerify(ctx, login, secret); err != nil {
		// The live service may already have accepted the candidate.
		return errors.Join(err, r.Transition(ctx, receipt.OperationID, "running", "reconcile_required"))
	}
	if err = r.Transition(ctx, receipt.OperationID, "running", "verifying"); err != nil {
		return err
	}
	return r.CompleteVerifiedCreate(ctx, receipt, version)
}

// CompleteVerifiedCreate publishes both outcomes after the worker verifies
// the applied credential. A retry with the same receipt is safe.
func (r *Registry) CompleteVerifiedCreate(ctx context.Context, receipt Receipt, expectedVersion int64) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var operation, state string
	var version int64
	err = tx.QueryRowContext(ctx, `SELECT o.status,u.status,u.row_version FROM operations o
 JOIN users u ON u.id=o.target_id WHERE o.id=? AND u.id=? AND o.kind='user.create'
 AND o.target_type='user' AND u.protected=0`, receipt.OperationID, receipt.UserID).Scan(&operation, &state, &version)
	if err != nil {
		return err
	}
	if operation == "succeeded" && state == "active" && version == expectedVersion+1 {
		return nil
	}
	if operation != "verifying" || state != "provisioning" || version != expectedVersion {
		return ErrJournalConflict
	}
	_, err = tx.ExecContext(ctx, `UPDATE users SET status='active',row_version=row_version+1,updated_at=CURRENT_TIMESTAMP WHERE id=?`, receipt.UserID)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE operations SET status='succeeded',finished_at=CURRENT_TIMESTAMP WHERE id=?`, receipt.OperationID)
	if err != nil {
		return err
	}
	return tx.Commit()
}
