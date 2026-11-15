package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

type PortableCredential struct {
	ID, Login, Status string
	Secret            vault.PlainSecret `json:"-"`
}

func portableStateDigest(ctx context.Context, q snapshotQuerier) (string, error) {
	var tables []portableTable
	for _, t := range portableColumns {
		rows, e := portableRows(ctx, q, t.name, t.columns)
		if e != nil {
			return "", e
		}
		tables = append(tables, portableTable{t.name, t.columns, rows})
	}
	// portableTable fields are private, so marshal row arrays explicitly.
	var values []any
	for _, t := range tables {
		values = append(values, []any{t.name, t.columns, t.rows})
	}
	raw, e := json.Marshal(values)
	if e != nil {
		return "", e
	}
	return digest(raw), nil
}
func (r *Registry) PortableCredentials(ctx context.Context) ([]PortableCredential, error) {
	rows, e := r.db.QueryContext(ctx, `SELECT u.id,u.login,u.status,c.secret_version,c.key_version,c.nonce,c.ciphertext FROM users u JOIN user_current_credentials a ON a.user_id=u.id JOIN credentials c ON c.id=a.credential_id AND c.user_id=u.id ORDER BY u.login COLLATE BINARY`)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	var out []PortableCredential
	for rows.Next() {
		var x PortableCredential
		var sv, kv uint64
		var n, c []byte
		if e = rows.Scan(&x.ID, &x.Login, &x.Status, &sv, &kv, &n, &c); e != nil {
			break
		}
		if kv != uint64(r.keyVersion) {
			e = ErrVaultKey
			break
		}
		x.Secret, e = r.vault.Decrypt(vault.Binding{UserID: x.ID, SecretVersion: sv, KeyVersion: kv}, n, c)
		if e != nil {
			break
		}
		out = append(out, x)
	}
	e = errors.Join(e, rows.Err())
	if e != nil {
		for _, x := range out {
			clear(x.Secret)
		}
		return nil, e
	}
	return out, nil
}
func (r *Registry) BeginPortableCutover(ctx context.Context, run, plan, installation string) (LegacyReceipt, error) {
	var out LegacyReceipt
	if !uuidMaintenance.MatchString(run) {
		return out, ErrInvalidMetadata
	}
	tx, e := r.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	hash, e := portableStateDigest(ctx, tx)
	if e != nil {
		return out, e
	}
	var receiptJSON string
	if e = tx.QueryRowContext(ctx, "SELECT summary FROM audit_runs WHERE script_version='portable-import-v1' AND coverage_hash=?", plan).Scan(&receiptJSON); e != nil {
		return out, ErrLegacyConflict
	}
	var approval struct {
		PostImport string `json:"post_import_sha256"`
	}
	if json.Unmarshal([]byte(receiptJSON), &approval) != nil || approval.PostImport != hash {
		return out, ErrLegacyDrift
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM audit_runs WHERE script_version='portable-import-v1' AND coverage_hash=?", plan).Scan(&n); e != nil || n != 1 {
		return out, ErrLegacyConflict
	}
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM legacy_migration_runs").Scan(&n); e != nil || n != 0 {
		return out, ErrLegacyConflict
	}
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM operations").Scan(&n); e != nil || n != 0 {
		return out, ErrLegacyConflict
	}
	if e = r.verifyVaultIdentity(ctx, tx); e != nil {
		return out, e
	}
	if e = r.verifyPriorCredentials(ctx, tx); e != nil {
		return out, e
	}
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM users WHERE login='master_user' AND status='active' AND protected=1 AND kind='service'").Scan(&n); e != nil || n != 1 {
		return out, ErrLegacyConflict
	}
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM users WHERE status NOT IN ('active','disabled','deleted')").Scan(&n); e != nil || n != 0 {
		return out, ErrLegacyConflict
	}
	out.OperationID = id()
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&out.Users); e != nil {
		return out, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,approved_at,status) VALUES(?,'importing',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'portable_staged')`, run, `{"portable_sha256":"`+hash+`","plan_sha256":"`+plan+`","installation_sha256":"`+installation+`"}`)
	if e != nil {
		return out, e
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO operations(id,actor_id,kind,target_type,target_id,status,idempotency_key,request_hash,correlation_id,created_at,started_at) VALUES(?,'local-portable','portable.import','migration',?,'running',?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, out.OperationID, run, "portable:"+run, hash, out.OperationID)
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}
func (r *Registry) CompletePortableCutover(ctx context.Context, run string, probe func(context.Context, string, vault.PlainSecret, bool) error, finalCheck func(context.Context) error) (LegacyReceipt, error) {
	var out LegacyReceipt
	if probe == nil || finalCheck == nil {
		return out, ErrInvalidMetadata
	}
	var expected string
	if e := r.db.QueryRowContext(ctx, `SELECT o.id,o.request_hash FROM operations o JOIN legacy_migration_runs m ON m.id=o.target_id WHERE m.id=? AND m.phase='importing' AND m.status='portable_staged' AND o.kind='portable.import' AND o.status='running'`, run).Scan(&out.OperationID, &expected); e != nil {
		return out, e
	}
	hash, e := portableStateDigest(ctx, r.db)
	if e != nil || hash != expected {
		return out, ErrLegacyDrift
	}
	credentials, e := r.PortableCredentials(ctx)
	if e != nil {
		return out, e
	}
	defer func() {
		for _, x := range credentials {
			clear(x.Secret)
		}
	}()
	for _, x := range credentials {
		if e = probe(ctx, x.Login, x.Secret, x.Status == "active"); e != nil {
			return out, e
		}
	}
	if e = finalCheck(ctx); e != nil {
		return out, e
	}
	tx, e := r.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	hash, e = portableStateDigest(ctx, tx)
	if e != nil || hash != expected {
		return out, ErrLegacyDrift
	}
	var n int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE status NOT IN ('succeeded','failed','cancelled','rolled_back') AND id<>?", out.OperationID).Scan(&n); e != nil || n != 0 {
		return out, ErrLegacyConflict
	}
	result, e := tx.ExecContext(ctx, "UPDATE operations SET status='succeeded',finished_at=CURRENT_TIMESTAMP WHERE id=? AND status='running' AND request_hash=?", out.OperationID, expected)
	if e != nil {
		return out, e
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return out, ErrLegacyConflict
	}
	result, e = tx.ExecContext(ctx, "UPDATE legacy_migration_runs SET phase='verified_cutover',status='verified_cutover',finished_at=CURRENT_TIMESTAMP WHERE id=? AND phase='importing' AND status='portable_staged'", run)
	if e != nil {
		return out, e
	}
	if n, e := result.RowsAffected(); e != nil || n != 1 {
		return out, ErrLegacyConflict
	}
	out.Users = len(credentials)
	return out, tx.Commit()
}

// Keep sql imported here for interface documentation compatibility.
var _ *sql.DB

// PortableCutoverState authorizes only replay of the same reviewed receipt.
func (r *Registry) PortableCutoverState(ctx context.Context, run, plan, installation string) (LegacyReceipt, string, error) {
	var out LegacyReceipt
	var raw, phase, hash string
	e := r.db.QueryRowContext(ctx, `SELECT o.id,o.status,o.request_hash,m.source_hashes FROM operations o JOIN legacy_migration_runs m ON m.id=o.target_id WHERE m.id=? AND o.kind='portable.import' AND o.target_type='migration'`, run).Scan(&out.OperationID, &phase, &hash, &raw)
	if e != nil {
		return out, "", e
	}
	var binding map[string]string
	if json.Unmarshal([]byte(raw), &binding) != nil || binding["plan_sha256"] != plan || binding["installation_sha256"] != installation || binding["portable_sha256"] != hash {
		return out, "", ErrLegacyConflict
	}
	actual, e := portableStateDigest(ctx, r.db)
	if e != nil || actual != hash {
		return out, "", ErrLegacyDrift
	}
	if e = r.db.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&out.Users); e != nil {
		return out, "", e
	}
	return out, phase, nil
}

func (r *Registry) BindPortableAuthHash(ctx context.Context, operation, hash string) error {
	if !hashPattern.MatchString(hash) {
		return ErrInvalidMetadata
	}
	var saved string
	e := r.db.QueryRowContext(ctx, "SELECT after_hash FROM operation_steps WHERE operation_id=? AND step_no=1 AND step_name='portable-auth'", operation).Scan(&saved)
	if e == nil {
		if saved != hash {
			return ErrLegacyDrift
		}
		return nil
	}
	if !errors.Is(e, sql.ErrNoRows) {
		return e
	}
	_, e = r.db.ExecContext(ctx, `INSERT INTO operation_steps(operation_id,step_no,step_name,state,after_hash,started_at,finished_at) SELECT id,1,'portable-auth','succeeded',?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP FROM operations WHERE id=? AND kind='portable.import' AND status='running'`, hash, operation)
	return e
}
func (r *Registry) PortableAuthHash(ctx context.Context, operation string) (string, error) {
	var hash string
	e := r.db.QueryRowContext(ctx, "SELECT after_hash FROM operation_steps WHERE operation_id=? AND step_no=1 AND step_name='portable-auth'", operation).Scan(&hash)
	return hash, e
}
