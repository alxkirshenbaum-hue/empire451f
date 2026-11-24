package storage

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// VerifiedCutoverReceipt reads a durable outcome after a lost response. It
// never restores an old generation or changes credentials on a replay.
func (r *Registry) VerifiedCutoverReceipt(ctx context.Context, run, ref string) (LegacyReceipt, error) {
	var receipt LegacyReceipt
	err := r.db.QueryRowContext(ctx, `SELECT o.id,(SELECT count(*) FROM legacy_migration_items WHERE run_id=r.id)
 FROM legacy_migration_runs r JOIN operations o ON o.target_id=r.id AND o.kind='legacy.cutover' AND o.status='succeeded'
 WHERE r.id=? AND r.phase='verified_cutover' AND r.status='verified_cutover' AND r.report_ref=?`, run, ref).Scan(&receipt.OperationID, &receipt.Users)
	return receipt, err
}

// CompleteLegacyCutover proves the imported secrets against the immutable
// snapshot, probes master and an independent user, then activates atomically.
// The caller holds the installation lock and finalCheck proves files/live Caddy.
func (r *Registry) CompleteLegacyCutover(ctx context.Context, snapshot, run, ref string, probe func(context.Context, string, vault.PlainSecret) error, finalCheck func(context.Context) error) (LegacyReceipt, error) {
	var empty LegacyReceipt
	if probe == nil || finalCheck == nil {
		return empty, ErrInvalidMetadata
	}
	generation, passwords, err := legacyInputs(snapshot)
	if err != nil {
		return empty, err
	}
	var source string
	if err = r.db.QueryRowContext(ctx, "SELECT source_hashes FROM legacy_migration_runs WHERE id=? AND phase='importing' AND status='working_handed_off' AND report_ref=? AND approved_at IS NOT NULL", run, ref).Scan(&source); err != nil {
		return empty, err
	}
	var hashes map[string]string
	if json.Unmarshal([]byte(source), &hashes) != nil || hashes["snapshot_sha256"] != generation {
		return empty, ErrLegacyDrift
	}
	type imported struct{ id, login, credential string }
	readImported := func(db rowQuerier, tx *sql.Tx) ([]imported, error) {
		var rows *sql.Rows
		var e error
		query := `SELECT u.id,u.login,c.id FROM users u JOIN legacy_migration_items m ON m.imported_user_id=u.id AND m.login_exact=u.login
 JOIN user_current_credentials a ON a.user_id=u.id JOIN credentials c ON c.id=a.credential_id AND c.user_id=u.id
 WHERE m.run_id=? AND u.source='legacy_import' AND u.status='provisioning' AND u.row_version=1 AND c.secret_version=1 AND c.revoked_at IS NULL
 AND ((u.login='master_user' AND u.protected=1 AND u.kind='service') OR (u.login!='master_user' AND u.protected=0 AND u.kind='regular')) ORDER BY u.login`
		if tx == nil {
			rows, e = r.db.QueryContext(ctx, query, run)
		} else {
			rows, e = tx.QueryContext(ctx, query, run)
		}
		if e != nil {
			return nil, e
		}
		var result []imported
		for rows.Next() {
			var row imported
			if e = rows.Scan(&row.id, &row.login, &row.credential); e != nil {
				rows.Close()
				return nil, e
			}
			result = append(result, row)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			return nil, e
		}
		var total, pending int
		if e = db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&total); e != nil {
			return nil, e
		}
		if e = db.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE status NOT IN ('succeeded','failed','cancelled','rolled_back')").Scan(&pending); e != nil {
			return nil, e
		}
		if len(result) != len(passwords) || total != len(result) || pending != 0 || len(result) < 2 || passwords["master_user"] == "" {
			return nil, ErrLegacyConflict
		}
		for _, row := range result {
			secret, e := r.openForPurpose(ctx, db, row.id, PrepareAuth)
			if e != nil {
				return nil, e
			}
			matches := bytes.Equal(secret, []byte(passwords[row.login]))
			clear(secret)
			if !matches {
				return nil, ErrLegacyDrift
			}
		}
		return result, nil
	}
	before, err := readImported(r.db, nil)
	if err != nil {
		return empty, err
	}
	regular := false
	for _, row := range before {
		if row.login != "master_user" && regular {
			continue
		}
		secret, e := r.OpenForPurpose(ctx, row.id, PrepareAuth)
		if e != nil {
			return empty, e
		}
		err = probe(ctx, row.login, secret)
		clear(secret)
		if err != nil {
			return empty, err
		}
		if row.login != "master_user" {
			regular = true
		}
	}
	if err = finalCheck(ctx); err != nil {
		return empty, err
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return empty, err
	}
	defer tx.Rollback()
	var ready int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM legacy_migration_runs WHERE id=? AND phase='importing' AND status='working_handed_off' AND report_ref=? AND source_hashes=?", run, ref, source).Scan(&ready); err != nil {
		return empty, err
	}
	if ready != 1 {
		return empty, ErrLegacyConflict
	}
	after, err := readImported(tx, tx)
	if err != nil {
		return empty, err
	}
	if len(after) != len(before) {
		return empty, ErrLegacyConflict
	}
	for i := range before {
		if before[i] != after[i] {
			return empty, ErrLegacyConflict
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE users SET status='active',row_version=row_version+1,updated_at=CURRENT_TIMESTAMP WHERE id IN (SELECT imported_user_id FROM legacy_migration_items WHERE run_id=?)", run); err != nil {
		return empty, err
	}
	receipt := LegacyReceipt{OperationID: id(), Users: len(after)}
	if _, err = tx.ExecContext(ctx, `INSERT INTO operations(id,actor_id,kind,target_type,target_id,status,idempotency_key,request_hash,correlation_id,created_at,started_at,finished_at)
 VALUES(?,'local-migration','legacy.cutover','migration',?,'succeeded',?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, receipt.OperationID, run, "cutover:"+run, generation, receipt.OperationID); err != nil {
		return empty, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE legacy_migration_runs SET phase='verified_cutover',status='verified_cutover',finished_at=CURRENT_TIMESTAMP WHERE id=?", run); err != nil {
		return empty, err
	}
	if err = tx.Commit(); err != nil {
		return empty, err
	}
	return receipt, nil
}

func (r *Registry) RequireCutoverReconciliation(ctx context.Context, run, ref string) error {
	_, err := r.db.ExecContext(ctx, "UPDATE legacy_migration_runs SET phase='reconcile_required',status='reconcile_required' WHERE id=? AND phase='importing' AND status='working_handed_off' AND report_ref=?", run, ref)
	return err
}
