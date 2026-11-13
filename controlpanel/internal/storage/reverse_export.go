package storage

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// ExportLegacy writes a v0.3.6 clients.json for offline review. It never
// replaces an existing export. The caller keeps all writers paused until use.
func (r *Registry) ExportLegacy(ctx context.Context, run, dir string) error {
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return errors.New("private output directory required")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var ready int
	err = tx.QueryRowContext(ctx, `SELECT count(*) FROM legacy_migration_runs WHERE id=? AND
 ((phase='importing' AND status='copy_handed_off') OR (phase='verified_cutover' AND status='verified_cutover'))`, run).Scan(&ready)
	if err != nil {
		return err
	}
	if ready != 1 {
		return ErrLegacyConflict
	}
	var pending int
	err = tx.QueryRowContext(ctx, `SELECT (SELECT count(*) FROM users WHERE status NOT IN ('active','disabled','deleted')) +
 (SELECT count(*) FROM operations WHERE status NOT IN ('succeeded','failed','cancelled','rolled_back'))`).Scan(&pending)
	if err != nil {
		return err
	}
	if pending != 0 {
		return ErrLegacyConflict
	}
	rows, err := tx.QueryContext(ctx, `SELECT u.id,u.login,c.secret_version,c.key_version,c.nonce,c.ciphertext
 FROM users u LEFT JOIN user_current_credentials b ON b.user_id=u.id
 LEFT JOIN credentials c ON c.id=b.credential_id AND c.user_id=u.id AND c.revoked_at IS NULL
 WHERE u.status='active' ORDER BY u.login COLLATE BINARY`)
	if err != nil {
		return err
	}
	defer rows.Close()
	type client struct {
		Login    string `json:"username"`
		Password string `json:"password"`
	}
	var clients []client
	master := false
	for rows.Next() {
		var id, login string
		var version, key uint64
		var nonce, sealed []byte
		if err := rows.Scan(&id, &login, &version, &key, &nonce, &sealed); err != nil {
			return err
		}
		if key != uint64(r.keyVersion) {
			return ErrVaultKey
		}
		plain, err := r.vault.Decrypt(vault.Binding{UserID: id, SecretVersion: version, KeyVersion: key}, nonce, sealed)
		if err != nil {
			return err
		}
		clients = append(clients, client{login, string(plain)})
		clear(plain)
		master = master || login == "master_user"
	}
	if err = rows.Err(); err != nil {
		return err
	}
	if !master || len(clients) > 101 {
		return ErrLegacyConflict
	}
	f, err := os.CreateTemp(dir, ".export-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	data := struct {
		Format  string   `json:"format"`
		Version int      `json:"schema_version"`
		Clients []client `json:"clients"`
	}{"empire-vpn-clients", 1, clients}
	if err = json.NewEncoder(f).Encode(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Link(f.Name(), filepath.Join(dir, "clients.json")); err != nil {
		return err
	}
	directory, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
