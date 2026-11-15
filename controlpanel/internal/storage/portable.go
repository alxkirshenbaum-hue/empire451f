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
	// Recognize only the canonical bootstrap catalog, including variants produced
	// by public InstallInitialSFA. Regenerate bodies rather than trusting labels.
	var templates, revisions, variants int
	if e := tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM profile_templates),(SELECT count(*) FROM template_revisions),(SELECT count(*) FROM profile_routing_variants)").Scan(&templates, &revisions, &variants); e != nil {
		return e
	}
	if templates == 0 {
		if revisions != 0 || variants != 0 {
			return ErrLegacyConflict
		}
		return nil
	}
	if templates != 1 || (variants != 0 && variants != 2) || revisions != 1+variants {
		return ErrLegacyConflict
	}
	var valid int
	if e := tx.QueryRowContext(ctx, "SELECT count(*) FROM profile_templates WHERE id='sfa' AND slug='sfa' AND name='SFA' AND enabled=1 AND transport='naive_https'").Scan(&valid); e != nil {
		return e
	}
	if valid != 1 {
		return ErrLegacyConflict
	}
	var root, body, hash string
	if e := tx.QueryRowContext(ctx, "SELECT id,body_json,sha256 FROM template_revisions WHERE template_id='sfa' AND semver='1.0.0' AND client_family='sfa' AND min_version='1.14.4' AND max_version IS NULL AND status='approved'").Scan(&root, &body, &hash); e != nil {
		return ErrLegacyConflict
	}
	if digest([]byte(body)) != hash {
		return ErrLegacyConflict
	}
	if variants == 0 {
		return nil
	}
	prepared, e := WithPanelDestination([]byte(body))
	if e != nil {
		return ErrLegacyConflict
	}
	base, e := DeriveBaseRouting(prepared)
	if e != nil {
		return ErrLegacyConflict
	}
	for _, variant := range []string{"base", "ru_download_manager"} {
		candidate := prepared
		minimum := "1.15.0-alpha.13"
		maximum := sql.NullString{String: minimum, Valid: true}
		if variant == "base" {
			candidate = base
			minimum = "1.14.4"
			maximum = sql.NullString{}
		}
		checksum := digest(candidate)
		var stored, sha, semver, min string
		var max sql.NullString
		e = tx.QueryRowContext(ctx, "SELECT v.body_json,v.sha256,v.semver,v.min_version,v.max_version FROM profile_routing_variants m JOIN template_revisions v ON v.id=m.revision_id WHERE m.source_revision_id=? AND m.variant=? AND m.policy_version=? AND v.template_id='sfa' AND v.client_family='sfa' AND v.status='approved'", root, variant, RoutingPolicyVersion).Scan(&stored, &sha, &semver, &min, &max)
		if e != nil || stored != string(candidate) || sha != checksum || semver != "w6-p2-"+variant+"-"+checksum[:16] || min != minimum || max != maximum {
			return ErrLegacyConflict
		}
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
	for _, spec := range []struct{ name, columns string }{{"profile_templates", "id,slug,name,transport,enabled"}, {"template_revisions", "id,template_id,semver,client_family,min_version,max_version,body_json,sha256,status,created_at,approved_at"}, {"profile_routing_variants", "source_revision_id,variant,policy_version,revision_id"}, {"admin_accounts", "id,username,password_hash,disabled,created_at,last_login_at"}, {"nodes", "id,alias,role,hostname_ref,last_seen_at,observed_source,checked_at,stale_after,health,row_version"}, {"vault_identity", "singleton,key_version,nonce,ciphertext"}} {
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
