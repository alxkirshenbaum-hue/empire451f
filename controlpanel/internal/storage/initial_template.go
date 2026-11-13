package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// InstallInitialSFA preserves an immutable explicitly reviewed revision on retry.
func (r *Registry) InstallInitialSFA(ctx context.Context, body []byte, approved string) (string, error) {
	if digest(body) != approved {
		return "", ErrLegacyDrift
	}
	var template struct{ Outbounds []struct{ Type string } }
	if json.Unmarshal(body, &template) != nil {
		return "", ErrInvalidMetadata
	}
	count := 0
	for _, o := range template.Outbounds {
		if o.Type == "naive" {
			count++
		}
	}
	if count != 1 {
		return "", ErrInvalidMetadata
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var revision string
	err = tx.QueryRowContext(ctx, "SELECT id FROM template_revisions WHERE template_id='sfa' AND sha256=? AND client_family='sfa' AND min_version='1.14.4' AND status='approved'", approved).Scan(&revision)
	if err == nil {
		return revision, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return "", err
	}
	var occupied int
	if err = tx.QueryRowContext(ctx, "SELECT (SELECT count(*) FROM profile_templates)+(SELECT count(*) FROM users)").Scan(&occupied); err != nil {
		return "", err
	}
	if occupied != 0 {
		return "", ErrLegacyConflict
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO profile_templates VALUES('sfa','sfa','SFA','naive_https',1)"); err != nil {
		return "", err
	}
	revision = id()
	if _, err = tx.ExecContext(ctx, `INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at,approved_at)
 VALUES(?,'sfa','1.0.0','sfa','1.14.4',?,?,'approved',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, revision, string(body), approved); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return revision, nil
}
