package storage

import "context"

// MasterOwnerCredential returns existing canonical credentials; caller clears secret.
func (r *Registry) MasterOwnerCredential(ctx context.Context) (id, cid string, secret []byte, err error) {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT u.id,cc.credential_id FROM users u JOIN user_current_credentials cc ON cc.user_id=u.id WHERE u.login='master_user' AND u.kind='service' AND u.protected=1 AND u.status='active'`).Scan(&id, &cid)
	if err != nil {
		return
	}
	plain, e := r.openForPurpose(ctx, tx, id, RenderProfile)
	if e != nil {
		err = e
		return
	}
	secret = []byte(plain)
	return
}
