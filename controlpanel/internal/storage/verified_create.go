package storage

import (
	"context"
	"errors"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

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
