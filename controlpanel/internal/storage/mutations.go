package storage

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

var ErrOperationInProgress = errors.New("conflicting operation in progress")

type MutationRequest struct {
	UserID          string
	Action          string
	ExpectedVersion int64
	Reason          string
	ConfirmDelete   bool
}

// QueueOwnedMutation stages intent and (for rotate only) one encrypted secret.
// It never changes effective user state, current credential, or Caddy.
func (r *Registry) QueueOwnedMutation(ctx context.Context, run, actor, key string, req MutationRequest) (Receipt, error) {
	if run == "" || actor == "" || key == "" || req.UserID == "" {
		return Receipt{}, ErrInvalidMetadata
	}
	if req.Action == "revoke" {
		req.Action = "disable"
	}
	if req.Action != "disable" && req.Action != "enable" && req.Action != "rotate" && req.Action != "delete" {
		return Receipt{}, ErrInvalidMetadata
	}
	if req.ExpectedVersion < 1 {
		return Receipt{}, ErrPreconditionRequired
	}
	if !utf8.ValidString(req.Reason) || len(req.Reason) > 512 || strings.ContainsRune(req.Reason, 0) || req.Action != "enable" && strings.TrimSpace(req.Reason) == "" || req.Action == "delete" && !req.ConfirmDelete {
		return Receipt{}, ErrInvalidMetadata
	}
	payload, _ := json.Marshal(struct {
		Run     string
		Request MutationRequest
	}{run, req})
	hash := digest(payload)
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	if err = requireVerifiedCutover(ctx, tx, run); err != nil {
		return Receipt{}, err
	}
	var rec Receipt
	var saved string
	err = tx.QueryRowContext(ctx, "SELECT id,target_id,request_hash FROM operations WHERE actor_id=? AND idempotency_key=?", actor, key).Scan(&rec.OperationID, &rec.UserID, &saved)
	if err == nil {
		if saved != hash {
			return Receipt{}, ErrIdempotencyConflict
		}
		return rec, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, err
	}
	u, err := scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id=?", req.UserID))
	if err != nil {
		return Receipt{}, err
	}
	if u.Protected || u.Login == "master_user" || u.Kind != "regular" {
		return Receipt{}, ErrProtectedAccount
	}
	var busy int
	err = tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE status IN ('reconcile_required','rollback_running') OR (target_type='user' AND target_id=? AND status IN ('queued','running','verifying'))", u.ID).Scan(&busy)
	if err != nil {
		return Receipt{}, err
	}
	if busy != 0 {
		return Receipt{}, ErrOperationInProgress
	}
	if u.Version != req.ExpectedVersion {
		return Receipt{}, ErrVersionConflict
	}
	if u.Status != "active" && u.Status != "disabled" {
		return Receipt{}, ErrInvalidTransition
	}
	next := u.Status
	switch req.Action {
	case "disable":
		next = "disabled"
	case "enable":
		next = "active"
	case "delete":
		next = "deleted"
	}
	if req.Action == "rotate" && u.Status != "active" {
		return Receipt{}, ErrInvalidTransition
	}
	var old string
	err = tx.QueryRowContext(ctx, "SELECT c.id FROM user_current_credentials x JOIN credentials c ON c.id=x.credential_id AND c.user_id=x.user_id WHERE x.user_id=? AND c.revoked_at IS NULL", u.ID).Scan(&old)
	if err != nil {
		return Receipt{}, err
	}
	fresh := old
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if req.Action == "rotate" {
		var version uint64
		if err = tx.QueryRowContext(ctx, "SELECT max(secret_version)+1 FROM credentials WHERE user_id=?", u.ID).Scan(&version); err != nil {
			return Receipt{}, err
		}
		entropy := make([]byte, 32)
		if _, err = rand.Read(entropy); err != nil {
			return Receipt{}, err
		}
		secret := base64.RawURLEncoding.AppendEncode(nil, entropy)
		clear(entropy)
		defer clear(secret)
		nonce, cipher, e := r.vault.Encrypt(vault.Binding{UserID: u.ID, SecretVersion: version, KeyVersion: uint64(r.keyVersion)}, secret)
		if e != nil {
			return Receipt{}, e
		}
		fresh = id()
		_, err = tx.ExecContext(ctx, "INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) VALUES(?,?,?,?,?,?,?,?)", fresh, u.ID, version, vault.Algorithm, nonce, cipher, r.keyVersion, stamp)
		if err != nil {
			return Receipt{}, err
		}
	}
	rec = Receipt{id(), u.ID}
	kind := "user." + req.Action
	if req.Action == "rotate" {
		kind = "credential.rotate"
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO operations(id,actor_id,kind,target_type,target_id,status,idempotency_key,request_hash,expected_version,correlation_id,created_at) VALUES(?,?,?,'user',?,'queued',?,?,?,?,?)", rec.OperationID, actor, kind, u.ID, key, hash, u.Version, rec.OperationID, stamp)
	if err != nil {
		return Receipt{}, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO user_mutations VALUES(?,?,?,?,?,?,?,?)", rec.OperationID, run, u.Status, next, old, fresh, req.Reason, u.Status == next && req.Action != "rotate")
	if err != nil {
		return Receipt{}, err
	}
	return rec, tx.Commit()
}

type AuthJob struct {
	Receipt
	Login, Kind, Phase, BeforeStatus, AfterStatus, OldCredential, NewCredential string
	Version                                                                     int64
	NoChange                                                                    bool
}

// OwnedAuthJob binds replay to the original run and immutable staged intent.
func (r *Registry) OwnedAuthJob(ctx context.Context, run, operation string) (AuthJob, error) {
	var j AuthJob
	if err := requireVerifiedCutover(ctx, r.db, run); err != nil {
		return j, err
	}
	err := r.db.QueryRowContext(ctx, "SELECT o.id,u.id,u.login,o.kind,o.status,u.row_version FROM operations o JOIN users u ON u.id=o.target_id WHERE o.id=? AND o.target_type='user' AND u.protected=0", operation).Scan(&j.OperationID, &j.UserID, &j.Login, &j.Kind, &j.Phase, &j.Version)
	if err != nil {
		return j, err
	}
	if j.Kind == "user.create" {
		_, _, _, err = r.OwnedCreateState(ctx, run, operation)
		if j.Phase == "queued" {
			err = nil
		} // ApplyCreate still verifies provisioning.
		j.AfterStatus = "active"
		return j, err
	}
	var actual, current string
	var expected int64
	err = r.db.QueryRowContext(ctx, "SELECT m.before_status,m.after_status,m.old_credential_id,m.new_credential_id,m.no_change,o.expected_version,u.status,c.credential_id FROM user_mutations m JOIN operations o ON o.id=m.operation_id JOIN users u ON u.id=o.target_id JOIN user_current_credentials c ON c.user_id=u.id WHERE m.operation_id=? AND m.owner_run=?", operation, run).Scan(&j.BeforeStatus, &j.AfterStatus, &j.OldCredential, &j.NewCredential, &j.NoChange, &expected, &actual, &current)
	if err != nil {
		return j, err
	}
	if j.Kind != "user.disable" && j.Kind != "user.enable" && j.Kind != "user.delete" && j.Kind != "credential.rotate" {
		return j, ErrJournalConflict
	}
	delta := int64(1)
	if j.NoChange {
		delta = 0
	}
	if j.Phase == "succeeded" {
		if actual != j.AfterStatus || current != j.NewCredential || j.Version != expected+delta {
			return j, ErrJournalConflict
		}
	} else if j.Phase == "queued" || j.Phase == "running" || j.Phase == "verifying" {
		if actual != j.BeforeStatus || current != j.OldCredential || j.Version != expected {
			return j, ErrJournalConflict
		}
	} else {
		return j, ErrJournalConflict
	}
	return j, nil
}

// WithMutationSecrets is worker-only: values are scoped to the callback and
// cleared afterwards, including staged v+1 on a replay.
func (r *Registry) WithMutationSecrets(ctx context.Context, j AuthJob, fn func(string, vault.PlainSecret, vault.PlainSecret) error) error {
	if fn == nil || j.Kind == "user.create" {
		return ErrInvalidMetadata
	}
	open := func(credential string) (vault.PlainSecret, error) {
		var v, k uint64
		var nonce, cipher []byte
		err := r.db.QueryRowContext(ctx, "SELECT secret_version,key_version,nonce,ciphertext FROM credentials WHERE id=? AND user_id=?", credential, j.UserID).Scan(&v, &k, &nonce, &cipher)
		if err != nil {
			return nil, err
		}
		if k != uint64(r.keyVersion) {
			return nil, ErrVaultKey
		}
		return r.vault.Decrypt(vault.Binding{UserID: j.UserID, SecretVersion: v, KeyVersion: k}, nonce, cipher)
	}
	old, err := open(j.OldCredential)
	if err != nil {
		return err
	}
	defer clear(old)
	fresh, err := open(j.NewCredential)
	if err != nil {
		return err
	}
	defer clear(fresh)
	return fn(j.Login, old, fresh)
}

// CompleteVerifiedMutation is called only after file/live/fresh-auth proof.
func (r *Registry) CompleteVerifiedMutation(ctx context.Context, run string, j AuthJob) error {
	observed, err := r.OwnedAuthJob(ctx, run, j.OperationID)
	if err != nil {
		return err
	}
	if observed.Receipt != j.Receipt || observed.Kind != j.Kind {
		return ErrJournalConflict
	}
	if observed.Phase == "succeeded" {
		return nil
	}
	if observed.Phase != "verifying" {
		return ErrJournalConflict
	}
	j = observed
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var affected sql.Result
	if !j.NoChange {
		affected, err = tx.ExecContext(ctx, "UPDATE users SET status=?,row_version=row_version+1,updated_at=CURRENT_TIMESTAMP,deleted_at=CASE WHEN ?='deleted' THEN CURRENT_TIMESTAMP ELSE deleted_at END WHERE id=? AND row_version=? AND status=? AND protected=0", j.AfterStatus, j.AfterStatus, j.UserID, j.Version, j.BeforeStatus)
		if err != nil {
			return err
		}
		n, e := affected.RowsAffected()
		if e != nil {
			return e
		}
		if n != 1 {
			return ErrVersionConflict
		}
	} else {
		var version int64
		if err = tx.QueryRowContext(ctx, "SELECT row_version FROM users WHERE id=? AND status=? AND protected=0", j.UserID, j.BeforeStatus).Scan(&version); err != nil {
			return err
		}
		if version != j.Version {
			return ErrVersionConflict
		}
	}
	affected, err = tx.ExecContext(ctx, "UPDATE user_current_credentials SET credential_id=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=? AND credential_id=?", j.NewCredential, j.UserID, j.OldCredential)
	if err != nil {
		return err
	}
	n, e := affected.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrJournalConflict
	}
	if j.NewCredential != j.OldCredential || j.AfterStatus == "deleted" {
		if _, err = tx.ExecContext(ctx, "UPDATE credentials SET revoked_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?", j.OldCredential, j.UserID); err != nil {
			return err
		}
	}
	if j.NewCredential != j.OldCredential {
		if _, err = tx.ExecContext(ctx, "UPDATE credentials SET rotated_at=CURRENT_TIMESTAMP WHERE id=? AND user_id=?", j.NewCredential, j.UserID); err != nil {
			return err
		}
	}
	affected, err = tx.ExecContext(ctx, "UPDATE operations SET status='succeeded',finished_at=CURRENT_TIMESTAMP WHERE id=? AND status='verifying'", j.OperationID)
	if err != nil {
		return err
	}
	n, e = affected.RowsAffected()
	if e != nil {
		return e
	}
	if n != 1 {
		return ErrJournalConflict
	}
	return tx.Commit()
}

func (r *Registry) NextOwnedAuth(ctx context.Context, run string) (Receipt, string, error) {
	var rec Receipt
	var phase string
	if err := requireVerifiedCutover(ctx, r.db, run); err != nil {
		return rec, phase, err
	}
	var blocked int
	err := r.db.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE status IN ('reconcile_required','rollback_running') OR (status IN ('running','verifying') AND kind NOT IN ('user.create','user.disable','user.enable','user.delete','credential.rotate'))").Scan(&blocked)
	if err != nil {
		return rec, phase, err
	}
	if blocked > 0 {
		return rec, phase, ErrJournalConflict
	}
	if err = r.db.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE status IN ('running','verifying')").Scan(&blocked); err != nil {
		return rec, phase, err
	}
	if blocked > 1 {
		return rec, phase, ErrJournalConflict
	}
	err = r.db.QueryRowContext(ctx, "SELECT id,target_id,status FROM operations WHERE kind IN ('user.create','user.disable','user.enable','user.delete','credential.rotate') AND target_type='user' AND status IN ('queued','running','verifying') ORDER BY CASE WHEN status='queued' THEN 1 ELSE 0 END,created_at,id LIMIT 1").Scan(&rec.OperationID, &rec.UserID, &phase)
	if errors.Is(err, sql.ErrNoRows) {
		return rec, "", nil
	}
	return rec, phase, err
}
