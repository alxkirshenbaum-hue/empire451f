package storage

import (
	"context"
	"database/sql"
	"errors"
)

// QueueOwnedCreate is the shared creation entry point after writer cutover.
// actor and key identify the caller's request; replay retains the original revision.
func (r *Registry) QueueOwnedCreate(ctx context.Context, run, actor, key, login string) (Receipt, error) {
	if actor == "" || key == "" || run == "" || !loginPattern.MatchString(login) || login == "master_user" {
		return Receipt{}, ErrInvalidMetadata
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	if err = requireVerifiedCutover(ctx, tx, run); err != nil {
		return Receipt{}, err
	}
	var receipt Receipt
	var previous string
	err = tx.QueryRowContext(ctx, `SELECT o.id,u.id,u.login FROM operations o JOIN users u ON u.id=o.target_id
 WHERE o.kind='user.create' AND o.actor_id=? AND o.idempotency_key=?`, actor, key).Scan(&receipt.OperationID, &receipt.UserID, &previous)
	if err == nil {
		if previous != login {
			return Receipt{}, ErrIdempotencyConflict
		}
		return receipt, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, err
	}
	var revision string
	err = tx.QueryRowContext(ctx, `SELECT v.id FROM template_revisions v JOIN profile_templates t ON t.id=v.template_id
 WHERE t.enabled=1 AND v.status='approved' AND v.client_family='sfa'
 ORDER BY julianday(COALESCE(v.approved_at,v.created_at)) DESC,v.id DESC LIMIT 1`).Scan(&revision)
	if err != nil {
		return Receipt{}, err
	}
	receipt, err = r.stageCreate(ctx, tx, actor, key, CreateRequest{Login: login, DisplayName: login, TemplateRevisionID: revision, TargetClient: "sfa"})
	if err != nil {
		return Receipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

// One gate shared by queue admission and execution; never advances migration.
func requireVerifiedCutover(ctx context.Context, db rowQuerier, run string) error {
	var ready int
	if err := db.QueryRowContext(ctx, "SELECT count(*) FROM legacy_migration_runs WHERE id=? AND phase='verified_cutover' AND status='verified_cutover'", run).Scan(&ready); err != nil {
		return err
	}
	if ready != 1 {
		return ErrLegacyConflict
	}
	return nil
}
