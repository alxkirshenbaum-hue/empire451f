package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
)

// Owner authenticates an independent panel account, never VPN credentials.
func (r *Registry) Owner(ctx context.Context, token string) (string, error) {
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	return status.SessionOwner(ctx, tx, token)
}
func (r *Registry) QueueOwnedUser(ctx context.Context, run, actor, key string, req CreateRequest) (Receipt, error) {
	if req.TargetClient != Client1144 && req.TargetClient != ClientAlpha13 {
		return Receipt{}, ErrTemplateIncompatible
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	if err = requireVerifiedCutover(ctx, tx, run); err != nil {
		return Receipt{}, err
	}
	receipt, err := r.stageCreateWithVariant(ctx, tx, actor, key, req, true)
	if err != nil {
		return Receipt{}, err
	}
	return receipt, tx.Commit()
}

type TemplateMetadata struct {
	ID      string  `json:"id"`
	Name    string  `json:"name"`
	Minimum string  `json:"min_version"`
	Maximum *string `json:"max_version,omitempty"`
	Variant string  `json:"variant"`
}

func (r *Registry) ApprovedTemplates(ctx context.Context) ([]TemplateMetadata, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT v.id,t.name,v.min_version,v.max_version,m.variant FROM profile_routing_variants m JOIN template_revisions v ON v.id=m.revision_id JOIN profile_templates t ON t.id=v.template_id WHERE t.enabled=1 AND v.status='approved' AND m.variant='base' AND m.policy_version=2 AND EXISTS(SELECT 1 FROM template_revisions s WHERE s.id=m.source_revision_id AND s.status='approved') ORDER BY v.created_at DESC,v.id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []TemplateMetadata{}
	for rows.Next() {
		var v TemplateMetadata
		if err = rows.Scan(&v.ID, &v.Name, &v.Minimum, &v.Maximum, &v.Variant); err != nil {
			return nil, err
		}
		result = append(result, v)
	}
	return result, rows.Err()
}

type CredentialMetadata struct {
	Version   int64   `json:"secret_version"`
	RotatedAt *string `json:"rotated_at,omitempty"`
	RevokedAt *string `json:"revoked_at,omitempty"`
	State     string  `json:"state"`
}

func (r *Registry) CredentialStatus(ctx context.Context, user string) (CredentialMetadata, error) {
	var v CredentialMetadata
	err := r.db.QueryRowContext(ctx, "SELECT c.secret_version,c.rotated_at,c.revoked_at,CASE WHEN EXISTS(SELECT 1 FROM operations o WHERE o.target_type='user' AND o.target_id=u.id AND o.status IN ('running','verifying','reconcile_required','rollback_running')) THEN 'reconcile_required' ELSE u.status END FROM user_current_credentials x JOIN credentials c ON c.id=x.credential_id AND c.user_id=x.user_id JOIN users u ON u.id=x.user_id WHERE x.user_id=?", user).Scan(&v.Version, &v.RotatedAt, &v.RevokedAt, &v.State)
	return v, err
}

type OperationMetadata struct {
	ID       string  `json:"operation_id"`
	Kind     string  `json:"kind"`
	Status   string  `json:"status"`
	Target   *string `json:"target_id,omitempty"`
	Created  string  `json:"created_at"`
	Finished *string `json:"finished_at,omitempty"`
}

func (r *Registry) OwnerOperations(ctx context.Context, actor, user string, limit int) ([]OperationMetadata, error) {
	if limit < 1 || limit > 100 {
		return nil, ErrInvalidMetadata
	}
	rows, err := r.db.QueryContext(ctx, "SELECT id,kind,status,target_id,created_at,finished_at FROM operations WHERE actor_id=? AND (?='' OR target_id=?) ORDER BY created_at DESC,id DESC LIMIT ?", actor, user, user, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []OperationMetadata{}
	for rows.Next() {
		var o OperationMetadata
		if err = rows.Scan(&o.ID, &o.Kind, &o.Status, &o.Target, &o.Created, &o.Finished); err != nil {
			return nil, err
		}
		result = append(result, o)
	}
	return result, rows.Err()
}

// QueueOwnedRename shares the same durable operation ledger and CAS primitive.
func (r *Registry) QueueOwnedRename(ctx context.Context, run, actor, key, user string, expected int64, name string) (Receipt, error) {
	if !validDisplayName(name) || actor == "" || key == "" {
		return Receipt{}, ErrInvalidMetadata
	}
	body, _ := json.Marshal([]any{"user.rename", run, user, expected, name})
	hash := digest(body)
	var receipt Receipt
	_, err := r.updateUserCASReplay(ctx, user, expected, func(tx *sql.Tx) (bool, error) {
		if err := requireVerifiedCutover(ctx, tx, run); err != nil {
			return false, err
		}
		var previous string
		e := tx.QueryRowContext(ctx, "SELECT id,target_id,request_hash FROM operations WHERE actor_id=? AND idempotency_key=?", actor, key).Scan(&receipt.OperationID, &receipt.UserID, &previous)
		if e == nil {
			if previous != hash {
				return false, ErrIdempotencyConflict
			}
			return true, nil
		}
		if !errors.Is(e, sql.ErrNoRows) {
			return false, e
		}
		receipt = Receipt{id(), user}
		return false, nil
	}, func(tx *sql.Tx, u UserMetadata) (UserMetadata, error) {
		updated, err := writeDisplayName(ctx, tx, user, expected, name)
		if err != nil {
			return updated, err
		}
		_, err = tx.ExecContext(ctx, "INSERT INTO operations(id,actor_id,kind,target_type,target_id,status,idempotency_key,request_hash,expected_version,correlation_id,created_at,finished_at) VALUES(?,?,'user.rename','user',?,'succeeded',?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)", receipt.OperationID, actor, user, key, hash, expected, receipt.OperationID)
		return updated, err
	})
	return receipt, err
}

type BackupMetadata struct {
	ID         string  `json:"id"`
	Created    string  `json:"created_at"`
	Size       int64   `json:"size_bytes"`
	Generation int64   `json:"source_generation"`
	Verified   *string `json:"verified_at,omitempty"`
	Status     string  `json:"status"`
}

func (r *Registry) BackupInventory(ctx context.Context) ([]BackupMetadata, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT id,created_at,size_bytes,source_generation,verified_at,status FROM backups ORDER BY created_at DESC LIMIT 100")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []BackupMetadata{}
	for rows.Next() {
		var b BackupMetadata
		if err = rows.Scan(&b.ID, &b.Created, &b.Size, &b.Generation, &b.Verified, &b.Status); err != nil {
			return nil, err
		}
		result = append(result, b)
	}
	return result, rows.Err()
}

type AuditMetadata struct {
	ID       string  `json:"id"`
	Started  string  `json:"started_at"`
	Finished *string `json:"finished_at,omitempty"`
	Checks   int     `json:"checks"`
}

func (r *Registry) AuditInventory(ctx context.Context) ([]AuditMetadata, error) {
	rows, err := r.db.QueryContext(ctx, "SELECT a.id,a.started_at,a.finished_at,(SELECT count(*) FROM audit_checks c WHERE c.audit_id=a.id) FROM audit_runs a ORDER BY a.started_at DESC LIMIT 30")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []AuditMetadata{}
	for rows.Next() {
		var a AuditMetadata
		if err = rows.Scan(&a.ID, &a.Started, &a.Finished, &a.Checks); err != nil {
			return nil, err
		}
		result = append(result, a)
	}
	return result, rows.Err()
}
func (r *Registry) UserPage(ctx context.Context, search, filter string, limit, offset int) ([]UserMetadata, error) {
	if len(search) > 96 || limit < 1 || limit > 100 || offset < 0 {
		return nil, ErrInvalidMetadata
	}
	switch filter {
	case "", "active", "disabled", "provisioning", "deleting", "deleted", "reconcile_required":
	default:
		return nil, ErrInvalidMetadata
	}
	// instr is case-sensitive; never normalize an exact login.
	rows, err := r.db.QueryContext(ctx, "SELECT * FROM (SELECT "+effectiveUserColumns+" FROM users) WHERE (?='' OR instr(login,?)>0 OR instr(display_name,?)>0) AND (?='' OR status=?) AND (?<>'' OR status<>'deleted') ORDER BY login COLLATE BINARY LIMIT ? OFFSET ?", search, search, search, filter, filter, filter, limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []UserMetadata{}
	for rows.Next() {
		u, e := scanUser(rows)
		if e != nil {
			return nil, e
		}
		result = append(result, u)
	}
	return result, rows.Err()
}

type PanelCounts struct {
	Regular   int `json:"regular"`
	Protected int `json:"protected"`
	Pending   int `json:"pending"`
}

func (r *Registry) Counts(ctx context.Context) (PanelCounts, error) {
	var c PanelCounts
	err := r.db.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM users WHERE kind='regular' AND status!='deleted'),(SELECT count(*) FROM users WHERE protected=1 AND status!='deleted'),(SELECT count(*) FROM operations WHERE status IN ('queued','running','verifying','rollback_running','reconcile_required'))").Scan(&c.Regular, &c.Protected, &c.Pending)
	return c, err
}

func (r *Registry) MutationReady(ctx context.Context, run string) (bool, error) {
	if run == "" {
		return false, nil
	}
	var ready int
	err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM legacy_migration_runs WHERE id=? AND phase='verified_cutover' AND status='verified_cutover'", run).Scan(&ready)
	return ready == 1, err
}
