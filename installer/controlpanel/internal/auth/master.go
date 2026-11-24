package auth

import (
	"context"
	"database/sql"
	"errors"
)

func (s *Service) RequireMaster(ctx context.Context) error {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM valid_master_admin WHERE (SELECT enabled FROM master_admin_policy WHERE singleton=1)=1 AND (SELECT count(*) FROM admin_accounts)=1`).Scan(&n)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("canonical master owner required")
	}
	return nil
}
func (s *Service) masterMode(ctx context.Context) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sqlite_schema WHERE type='table' AND name='master_admin_policy'`).Scan(&n)
	if err != nil || n == 0 {
		return false, err
	}
	err = s.db.QueryRowContext(ctx, `SELECT enabled FROM master_admin_policy WHERE singleton=1`).Scan(&n)
	return n == 1, err
}

// BindMaster binds the existing VPN master; no new user or plaintext storage.
func (s *Service) BindMaster(ctx context.Context, id, cid string, secret []byte) error {
	if len(secret) < 1 || len(secret) > 256 {
		return errors.New("invalid master credential")
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE master_admin_policy SET enabled=enabled WHERE singleton=1`); err != nil {
		return err
	}
	var n int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM users u JOIN user_current_credentials cc ON cc.user_id=u.id JOIN credentials c ON c.id=cc.credential_id WHERE u.id=? AND cc.credential_id=? AND u.login='master_user' AND u.kind='service' AND u.protected=1 AND u.status='active' AND c.revoked_at IS NULL`, id, cid).Scan(&n)
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("current active master required")
	}
	var aid, name, hash string
	err = tx.QueryRowContext(ctx, `SELECT id,username,password_hash FROM admin_accounts`).Scan(&aid, &name, &hash)
	if err == nil {
		var bid, bcid string
		if e := tx.QueryRowContext(ctx, `SELECT admin_id,credential_id FROM master_admin_binding WHERE singleton=1`).Scan(&bid, &bcid); e != nil {
			return errors.New("owner conflict")
		}
		if aid != id || name != "master_user" || bid != id || bcid != cid || !verify(string(secret), hash) {
			return errors.New("owner conflict")
		}
		if e := tx.QueryRowContext(ctx, `SELECT count(*) FROM admin_accounts`).Scan(&n); e != nil || n != 1 {
			return errors.New("owner conflict")
		}
	} else if errors.Is(err, sql.ErrNoRows) {
		salt := randomBytes(16)
		hash = prefix + encoding.EncodeToString(salt) + "$" + encoding.EncodeToString(derive(string(secret), salt))
		if _, err = tx.ExecContext(ctx, `INSERT INTO master_admin_binding VALUES(1,?,?)`, id, cid); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO admin_accounts(id,username,password_hash,created_at) VALUES(?,'master_user',?,CURRENT_TIMESTAMP)`, id, hash); err != nil {
			return err
		}
	} else {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE master_admin_policy SET enabled=1 WHERE singleton=1`); err != nil {
		return err
	}
	return tx.Commit()
}
