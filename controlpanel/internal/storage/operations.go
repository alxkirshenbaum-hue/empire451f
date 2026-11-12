package storage

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"time"
)

var ErrJournalConflict = errors.New("operation status or step conflicts with journal")
var ErrInvalidStep = errors.New("invalid operation checkpoint")
var hashPattern = regexp.MustCompile("^[0-9a-f]{64}$")
var codePattern = regexp.MustCompile("^[A-Z][A-Z0-9_]{0,63}$")

// A checkpoint contains metadata only. Number is supplied by the worker so
// a retry after losing the commit acknowledgement addresses the same step.
type Checkpoint struct {
	Number                           int
	Name, State                      string
	Started, Finished                time.Time
	BeforeHash, AfterHash, ErrorCode string
}
type InterruptedOperation struct {
	ID, Kind, Status string
	LastStep         int
}
type OperationJournal interface {
	AppendStep(context.Context, string, string, Checkpoint) error
	Transition(context.Context, string, string, string) error
	FindUnfinished(context.Context) ([]InterruptedOperation, error)
}

var _ OperationJournal = (*Registry)(nil)

func validMove(from, to string) bool {
	switch from {
	case "queued":
		return to == "running" || to == "cancelled"
	case "running":
		return to == "verifying" || to == "failed" || to == "rollback_running" || to == "reconcile_required"
	case "verifying":
		return to == "succeeded" || to == "rollback_running" || to == "failed" || to == "reconcile_required"
	case "rollback_running":
		return to == "rolled_back" || to == "reconcile_required"
	default:
		return false
	}
}

// Transition compares the persisted status with the worker's expectation.
// Reconciliation requires a separate recovery decision.
func (r *Registry) Transition(ctx context.Context, id, from, to string) error {
	if !validMove(from, to) {
		return ErrJournalConflict
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	res, err := r.db.ExecContext(ctx, `UPDATE operations SET status=?,
 started_at=CASE WHEN ?='running' THEN COALESCE(started_at,?) ELSE started_at END,
 finished_at=CASE WHEN ? IN ('succeeded','failed','cancelled','rolled_back') THEN ? ELSE finished_at END
 WHERE id=? AND status=?`, to, to, now, to, now, id, from)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrJournalConflict
	}
	return nil
}

func (c Checkpoint) valid() bool {
	switch c.Name {
	case "inspect", "snapshot", "render", "validate", "prepare", "apply", "verify", "rollback", "commit", "cleanup":
	default:
		return false
	}
	return c.Number > 0 && (c.State == "succeeded" || c.State == "failed") &&
		!c.Started.IsZero() && !c.Finished.Before(c.Started) &&
		(c.BeforeHash == "" || hashPattern.MatchString(c.BeforeHash)) &&
		(c.AfterHash == "" || hashPattern.MatchString(c.AfterHash)) &&
		((c.State == "succeeded" && c.ErrorCode == "") || (c.State == "failed" && codePattern.MatchString(c.ErrorCode)))
}

func (r *Registry) AppendStep(ctx context.Context, id, expected string, c Checkpoint) error {
	if !c.valid() {
		return ErrInvalidStep
	}
	if expected != "running" && expected != "verifying" && expected != "rollback_running" {
		return ErrJournalConflict
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var state string
	if err = tx.QueryRowContext(ctx, "SELECT status FROM operations WHERE id=?", id).Scan(&state); err != nil {
		return err
	}
	start, end := c.Started.UTC().Format(time.RFC3339Nano), c.Finished.UTC().Format(time.RFC3339Nano)
	var matches bool
	err = tx.QueryRowContext(ctx, `SELECT step_name=? AND state=? AND started_at=? AND finished_at IS ?
 AND COALESCE(before_hash,'')=? AND COALESCE(after_hash,'')=? AND COALESCE(error_code,'')=?
 FROM operation_steps WHERE operation_id=? AND step_no=?`, c.Name, c.State, start, end, c.BeforeHash, c.AfterHash, c.ErrorCode, id, c.Number).Scan(&matches)
	if err == nil {
		if !matches {
			return ErrJournalConflict
		}
		return nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if state != expected {
		return ErrJournalConflict
	}
	var next int
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE(MAX(step_no),0)+1 FROM operation_steps WHERE operation_id=?", id).Scan(&next); err != nil {
		return err
	}
	if next != c.Number {
		return ErrJournalConflict
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO operation_steps(operation_id,step_no,step_name,state,started_at,finished_at,before_hash,after_hash,error_code)
 VALUES(?,?,?,?,?,?,NULLIF(?,''),NULLIF(?,''),NULLIF(?,''))`, id, c.Number, c.Name, c.State, start, end, c.BeforeHash, c.AfterHash, c.ErrorCode)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// FindUnfinished is a read-only startup scan for interrupted work (§6.1).
// Queued jobs and jobs awaiting manual reconciliation have separate owners.
func (r *Registry) FindUnfinished(ctx context.Context) ([]InterruptedOperation, error) {
	rows, err := r.db.QueryContext(ctx, `SELECT o.id,o.kind,o.status,
 (SELECT COALESCE(MAX(step_no),0) FROM operation_steps WHERE operation_id=o.id)
 FROM operations o WHERE o.status IN ('running','verifying','rollback_running') ORDER BY o.created_at,o.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []InterruptedOperation{}
	for rows.Next() {
		var op InterruptedOperation
		if err := rows.Scan(&op.ID, &op.Kind, &op.Status, &op.LastStep); err != nil {
			return nil, err
		}
		result = append(result, op)
	}
	return result, rows.Err()
}
