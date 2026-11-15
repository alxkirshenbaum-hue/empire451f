package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"io"
	"os"
	"strings"
)

// PortablePlan is non-secret metadata; it authorizes only an offline first-start
// candidate. The caller holds the common installation writer, never a live DB.
type PortablePlan struct {
	Hash                  string `json:"plan_sha256"`
	Users                 int    `json:"users"`
	ReplaceInitialCatalog bool   `json:"replace_initial_template_catalog"`
}
type portableTable struct {
	name, columns string
	rows          [][]any
}

var portableColumns = []struct{ name, columns string }{
	{"profile_templates", "id,slug,name,transport,enabled"},
	{"template_revisions", "id,template_id,semver,client_family,min_version,max_version,body_json,sha256,status,created_at,approved_at"},
	{"profile_routing_variants", "source_revision_id,variant,policy_version,revision_id"},
	{"users", "id,login,kind,protected,source,display_name,status,created_at,updated_at,deleted_at,row_version"},
	{"credentials", "id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at,rotated_at,revoked_at"},
	{"user_current_credentials", "user_id,credential_id,updated_at"},
	{"user_profiles", "id,user_id,template_revision_id,target_client,last_issued_at"},
}

func portableRows(ctx context.Context, q snapshotQuerier, name, columns string) ([][]any, error) {
	rows, e := q.QueryContext(ctx, "SELECT "+columns+" FROM "+name+" ORDER BY 1,2")
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	count := len(strings.Split(columns, ","))
	result := [][]any{}
	for rows.Next() {
		values := make([]any, count)
		ptr := make([]any, count)
		for i := range ptr {
			ptr[i] = &values[i]
		}
		if e = rows.Scan(ptr...); e != nil {
			return nil, e
		}
		for i, v := range values {
			if b, ok := v.([]byte); ok {
				values[i] = append([]byte(nil), b...)
			}
		}
		result = append(result, values)
	}
	return result, rows.Err()
}
func portableClean(ctx context.Context, tx *sql.Tx) error {
	var count int
	for _, table := range []string{"users", "credentials", "user_profiles", "profile_issuance", "operations", "legacy_migration_runs", "config_revisions"} {
		if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM "+table).Scan(&count); e != nil {
			return e
		}
		if count != 0 {
			return ErrLegacyConflict
		}
	}
	// Only the untouched bootstrap catalog can be explicitly replaced. No custom
	// revisions or variants are silently discarded.
	if e := tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM profile_templates WHERE id<>'sfa' OR slug<>'sfa' OR name<>'SFA' OR enabled<>1 OR transport<>'naive_https')+(SELECT count(*) FROM template_revisions WHERE template_id<>'sfa' OR semver<>'1.0.0' OR client_family<>'sfa' OR min_version<>'1.14.4' OR status<>'approved')+(SELECT count(*) FROM profile_routing_variants)`).Scan(&count); e != nil {
		return e
	}
	if count != 0 {
		return ErrLegacyConflict
	}
	return nil
}
func (r *Registry) portable(ctx context.Context, path string, key *vault.Vault, owner, own, expected string, replace, apply bool) (PortablePlan, error) {
	var out PortablePlan
	if !uuidMaintenance.MatchString(owner) || own != "" && !uuidMaintenance.MatchString(own) {
		return out, ErrInvalidMetadata
	}
	before, e := portableRead(path)
	if e != nil {
		return out, e
	}
	if int64(len(before)) > SnapshotMaxBytes {
		return out, ErrSnapshotState
	}
	defer clear(before)
	if _, e = InspectCapturedSnapshot(ctx, path, key, owner, own); e != nil {
		return out, e
	}
	source, e := sql.Open("sqlite3", snapshotURI(path)+"?mode=ro&_query_only=on")
	if e != nil {
		return out, e
	}
	defer source.Close()
	tables := []portableTable{}
	for _, spec := range portableColumns {
		rows, e := portableRows(ctx, source, spec.name, spec.columns)
		if e != nil {
			return out, e
		}
		tables = append(tables, portableTable{spec.name, spec.columns, rows})
		if spec.name == "users" {
			out.Users = len(rows)
		}
	}
	after, e := portableRead(path)
	if e != nil {
		return out, e
	}
	defer clear(after)
	if digest(before) != digest(after) {
		return out, ErrSnapshotState
	}
	tx, e := r.db.BeginTx(ctx, nil)
	if e != nil {
		return out, e
	}
	defer tx.Rollback()
	if e = portableClean(ctx, tx); e != nil {
		return out, e
	}
	if e = r.verifyVaultIdentity(ctx, tx); e != nil {
		return out, e
	}
	baseline := []any{digest(before), owner, own}
	for _, spec := range []struct{ name, columns string }{{"profile_templates", "id,slug,name,transport,enabled"}, {"template_revisions", "id,template_id,semver,client_family,min_version,max_version,body_json,sha256,status,created_at,approved_at"}, {"admin_accounts", "id,username,password_hash,disabled,created_at,last_login_at"}, {"nodes", "id,alias,role,hostname_ref,last_seen_at,observed_source,checked_at,stale_after,health,row_version"}, {"vault_identity", "singleton,key_version,nonce,ciphertext"}} {
		rows, e := portableRows(ctx, tx, spec.name, spec.columns)
		if e != nil {
			return out, e
		}
		baseline = append(baseline, rows)
	}
	var templates int
	if e = tx.QueryRowContext(ctx, "SELECT count(*) FROM profile_templates").Scan(&templates); e != nil {
		return out, e
	}
	out.ReplaceInitialCatalog = templates > 0
	raw, e := json.Marshal(baseline)
	if e != nil {
		return out, e
	}
	out.Hash = digest(raw)
	if !apply {
		return out, nil
	}
	if expected != out.Hash || out.ReplaceInitialCatalog && !replace {
		return out, ErrLegacyConflict
	}
	for _, table := range []string{"profile_routing_variants", "template_revisions", "profile_templates"} {
		if _, e = tx.ExecContext(ctx, "DELETE FROM "+table); e != nil {
			return out, e
		}
	}
	for _, table := range tables {
		for _, values := range table.rows {
			if table.name == "credentials" {
				uid := values[1].(string)
				sv := values[2].(int64)
				kv := values[6].(int64)
				plain, e := key.Decrypt(vault.Binding{UserID: uid, SecretVersion: uint64(sv), KeyVersion: uint64(kv)}, values[4].([]byte), values[5].([]byte))
				if e != nil {
					clear(plain)
					return out, ErrVaultKey
				}
				nonce, cipher, e := r.vault.Encrypt(vault.Binding{UserID: uid, SecretVersion: uint64(sv), KeyVersion: uint64(r.keyVersion)}, plain)
				clear(plain)
				if e != nil {
					return out, e
				}
				values[4] = nonce
				values[5] = cipher
				values[6] = r.keyVersion
			}
			placeholders := strings.TrimSuffix(strings.Repeat("?,", len(values)), ",")
			if _, e = tx.ExecContext(ctx, "INSERT INTO "+table.name+"("+table.columns+") VALUES("+placeholders+")", values...); e != nil {
				return out, e
			}
		}
	}
	if e = r.verifyPriorCredentials(ctx, tx); e != nil {
		return out, e
	}
	check, e := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if e != nil {
		return out, e
	}
	bad := check.Next()
	e = errors.Join(check.Err(), check.Close())
	if e != nil {
		return out, e
	}
	if bad {
		return out, ErrSnapshotState
	}
	_, e = tx.ExecContext(ctx, `INSERT INTO audit_runs(id,script_version,started_at,finished_at,summary,coverage_hash) VALUES(?,'portable-import-v1',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'Offline first-start portable users imported; destination owner/key retained',?)`, id(), out.Hash)
	if e != nil {
		return out, e
	}
	return out, tx.Commit()
}
func (r *Registry) PreviewPortable(ctx context.Context, path string, key *vault.Vault, owner, own string) (PortablePlan, error) {
	return r.portable(ctx, path, key, owner, own, "", false, false)
}
func (r *Registry) ImportPortable(ctx context.Context, path string, key *vault.Vault, owner, own, expected string, replaceInitial bool) (PortablePlan, error) {
	return r.portable(ctx, path, key, owner, own, expected, replaceInitial, true)
}

func portableRead(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	i, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() || i.Size() > SnapshotMaxBytes {
		return nil, ErrSnapshotState
	}
	b, e := io.ReadAll(io.LimitReader(f, SnapshotMaxBytes+1))
	if int64(len(b)) > SnapshotMaxBytes {
		clear(b)
		return nil, ErrSnapshotState
	}
	return b, e
}
