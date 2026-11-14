package storage

import (
	"bytes"
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/migrations"
)

type snapshotQuerier interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
}

var registryMigrationScripts = []string{migrations.Registry, migrations.VaultIdentity, migrations.MigrationDocuments, migrations.ProfileIssuance, migrations.UserMutations, migrations.ProfileRouting, migrations.ProfilePanelDNS}

var ErrSnapshotState = errors.New("registry snapshot state is not clean")

// SnapshotInspection contains aggregate metadata only. It is not backup verification.
type SnapshotInspection struct {
	SchemaVersion     int `json:"schema_version"`
	Users             int `json:"users"`
	Credentials       int `json:"credentials"`
	PendingOperations int `json:"pending_operations"`
}

// verifyVaultIdentity is shared by ordinary Open and snapshot inspection.
func (r *Registry) verifyVaultIdentity(ctx context.Context, tx snapshotQuerier) error {
	var nonce, ciphertext []byte
	var version int64
	if err := tx.QueryRowContext(ctx, "SELECT key_version,nonce,ciphertext FROM vault_identity WHERE singleton=1").Scan(&version, &nonce, &ciphertext); err != nil {
		return err
	}
	plain, err := r.vault.Decrypt(vault.Binding{UserID: "!registry-key-check", SecretVersion: 1, KeyVersion: uint64(r.keyVersion)}, nonce, ciphertext)
	defer clear(plain)
	if err != nil || version != r.keyVersion || !bytes.Equal(plain, []byte("vpn-control registry key v1")) {
		return ErrVaultKey
	}
	return nil
}

// InspectSnapshot checks one consistent view of an already-open canonical registry.
// Caller must separately hold the installation writer and inspect file/prepared
// intents. This does not create/verify a backup or invent a DB generation. The
// view uses explicit BEGIN on a dedicated connection to avoid the driver's
// configured BEGIN IMMEDIATE. No data-changing statements are issued.
func (r *Registry) InspectSnapshot(ctx context.Context, ownBackupOperationID string) (SnapshotInspection, error) {
	zero := SnapshotInspection{}
	tx, err := r.db.Conn(ctx)
	if err != nil {
		return zero, err
	}
	defer tx.Close()
	if _, err = tx.ExecContext(ctx, "BEGIN"); err != nil {
		return zero, err
	}
	defer func() {
		if _, e := tx.ExecContext(context.Background(), "ROLLBACK"); e != nil {
			_ = tx.Raw(func(any) error { return driver.ErrBadConn })
		}
	}()
	var integrity string
	if err = tx.QueryRowContext(ctx, "PRAGMA integrity_check").Scan(&integrity); err != nil {
		return zero, err
	}
	if integrity != "ok" {
		return zero, ErrSnapshotState
	}
	rows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return zero, err
	}
	bad := rows.Next()
	rowErr := rows.Err()
	rows.Close()
	if rowErr != nil {
		return zero, rowErr
	}
	if bad {
		return zero, ErrSnapshotState
	}
	rows, err = tx.QueryContext(ctx, "SELECT version,sha256 FROM schema_migrations ORDER BY version")
	if err != nil {
		return zero, err
	}
	count := 0
	for rows.Next() {
		var version int
		var saved string
		if err = rows.Scan(&version, &saved); err != nil {
			rows.Close()
			return zero, err
		}
		if count >= len(registryMigrationScripts) || version != count+1 || saved != digest([]byte(registryMigrationScripts[count])) {
			rows.Close()
			return zero, ErrSnapshotState
		}
		count++
	}
	rowErr = rows.Err()
	rows.Close()
	if rowErr != nil {
		return zero, rowErr
	}
	if count != len(registryMigrationScripts) {
		return zero, ErrSnapshotState
	}
	if err = r.verifyVaultIdentity(ctx, tx); err != nil {
		return zero, err
	}
	if err = r.verifyPriorCredentials(ctx, tx); err != nil {
		return zero, err
	}
	if ownBackupOperationID != "" {
		var kind, state string
		if err = tx.QueryRowContext(ctx, "SELECT kind,status FROM operations WHERE id=?", ownBackupOperationID).Scan(&kind, &state); err != nil || kind != "backup.create" || state != "running" {
			return zero, ErrSnapshotState
		}
	}
	var pending int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM operations WHERE status IN ('queued','running','verifying','rollback_running','reconcile_required') AND (?='' OR id<>?)", ownBackupOperationID, ownBackupOperationID).Scan(&pending); err != nil {
		return zero, err
	}
	if pending != 0 {
		return zero, ErrSnapshotState
	}
	checks := []string{
		"SELECT count(*) FROM users WHERE status NOT IN ('active','disabled','deleted')",
		"SELECT CASE WHEN count(*)=1 THEN 0 ELSE 1 END FROM users WHERE login='master_user' AND kind='service' AND protected=1 AND status='active' AND deleted_at IS NULL",
		"SELECT count(*) FROM users WHERE (login<>'master_user' AND (kind<>'regular' OR protected<>0)) OR (status='deleted' AND deleted_at IS NULL) OR (status<>'deleted' AND deleted_at IS NOT NULL)",
		"SELECT count(*) FROM users u LEFT JOIN user_current_credentials x ON x.user_id=u.id LEFT JOIN credentials c ON c.id=x.credential_id AND c.user_id=x.user_id WHERE c.id IS NULL OR (u.status IN ('active','disabled') AND c.revoked_at IS NOT NULL) OR (u.status='deleted' AND c.revoked_at IS NULL)",
		"SELECT CASE WHEN count(*)<=100 THEN 0 ELSE 1 END FROM users WHERE kind='regular' AND status<>'deleted'",
	}
	for _, query := range checks {
		var n int
		if err = tx.QueryRowContext(ctx, query).Scan(&n); err != nil {
			return zero, err
		}
		if n != 0 {
			return zero, ErrSnapshotState
		}
	}
	out := SnapshotInspection{SchemaVersion: count}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM users").Scan(&out.Users); err != nil {
		return zero, err
	}
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM credentials").Scan(&out.Credentials); err != nil {
		return zero, err
	}
	return out, nil
}
