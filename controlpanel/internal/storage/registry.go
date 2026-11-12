// Package storage persists desired state. Workers apply queued operations separately.
package storage

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/migrations"
	_ "github.com/mattn/go-sqlite3"
)

var ErrIdempotencyConflict = errors.New("idempotency key reused with a different request")
var ErrVaultKey = errors.New("registry key verification failed")
var loginPattern = regexp.MustCompile("^[A-Za-z0-9][A-Za-z0-9_-]{0,47}$")

type Registry struct {
	db         *sql.DB
	vault      *vault.Vault
	keyVersion int64
}

// Open expects a private directory provisioned by the caller. Credentials are
// decrypted only via the worker's explicit lookup, never in operation receipts.
func Open(ctx context.Context, path string, cipher *vault.Vault, keyVersion int64) (*Registry, error) {
	if cipher == nil || keyVersion < 1 {
		return nil, errors.New("missing credential key or version")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	if !dir.IsDir() || runtime.GOOS != "windows" && dir.Mode().Perm()&0077 != 0 {
		return nil, errors.New("registry directory must be private")
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		info, err := os.Lstat(path + suffix)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
			return nil, errors.New("unsafe registry file or sidecar")
		}
	}
	// Closing a separate descriptor for an existing DB can release SQLite's
	// process-wide POSIX locks while another connection still owns the WAL.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err == nil {
		if err = f.Close(); err != nil {
			return nil, err
		}
	} else if !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	if runtime.GOOS == "windows" && !strings.HasPrefix(uri.Path, "/") {
		uri.Path = "/" + uri.Path
	}
	db, err := sql.Open("sqlite3", uri.String()+"?_journal_mode=WAL&_foreign_keys=on&_synchronous=FULL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	r := &Registry{db, cipher, keyVersion}
	if err = r.migrate(ctx); err != nil {
		db.Close()
		return nil, err
	}
	return r, nil
}

func (r *Registry) Close() error { return r.db.Close() }

func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func (r *Registry) migrate(ctx context.Context) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'").Scan(&count); err != nil {
		return err
	}
	scripts := []string{migrations.Registry, migrations.VaultIdentity, migrations.MigrationDocuments}
	if count != 0 {
		if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM schema_migrations").Scan(&count); err != nil {
			return err
		}
		if count < 1 || count > len(scripts) {
			return errors.New("unsupported registry schema")
		}
	}
	for i, script := range scripts {
		checksum := digest([]byte(script))
		if i < count {
			var saved string
			if err = tx.QueryRowContext(ctx, "SELECT sha256 FROM schema_migrations WHERE version=?", i+1).Scan(&saved); err != nil {
				return err
			}
			if saved != checksum {
				return errors.New("registry migration checksum mismatch")
			}
			continue
		}
		if _, err = tx.ExecContext(ctx, script); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO schema_migrations VALUES (?,?,?)", i+1, checksum, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	binding := vault.Binding{UserID: "!registry-key-check", SecretVersion: 1, KeyVersion: uint64(r.keyVersion)}
	marker := []byte("vpn-control registry key v1")
	if count < 2 {
		// Version 1 has no key marker. Authenticate every existing row before
		// assigning a key identity. Any failure rolls back the schema change.
		if err = r.verifyPriorCredentials(ctx, tx); err != nil {
			return err
		}
		nonce, ciphertext, err := r.vault.Encrypt(binding, marker)
		if err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "INSERT INTO vault_identity VALUES(1,?,?,?)", r.keyVersion, nonce, ciphertext); err != nil {
			return err
		}
	} else {
		var nonce, ciphertext []byte
		var version int64
		if err = tx.QueryRowContext(ctx, "SELECT key_version,nonce,ciphertext FROM vault_identity WHERE singleton=1").Scan(&version, &nonce, &ciphertext); err != nil {
			return err
		}
		plain, err := r.vault.Decrypt(binding, nonce, ciphertext)
		if err != nil || version != r.keyVersion || !bytes.Equal(plain, marker) {
			return ErrVaultKey
		}
	}
	return tx.Commit()
}

func (r *Registry) verifyPriorCredentials(ctx context.Context, tx *sql.Tx) error {
	rows, err := tx.QueryContext(ctx, "SELECT user_id,secret_version,key_version,nonce,ciphertext FROM credentials")
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var binding vault.Binding
		var nonce, ciphertext []byte
		if err := rows.Scan(&binding.UserID, &binding.SecretVersion, &binding.KeyVersion, &nonce, &ciphertext); err != nil {
			return err
		}
		if binding.KeyVersion != uint64(r.keyVersion) {
			return errors.New("required credential key version unavailable")
		}
		plain, err := r.vault.Decrypt(binding, nonce, ciphertext)
		if err != nil {
			return errors.New("existing credential key verification failed")
		}
		clear(plain)
	}
	return rows.Err()
}

type CreateRequest struct{ Login, DisplayName, TemplateRevisionID, TargetClient string }
type Receipt struct{ OperationID, UserID string }

func id() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&15 | 64
	b[8] = b[8]&63 | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// QueueCreate commits the credential, current binding and operation together.
// actor is the authenticated principal supplied by the application layer.
func (r *Registry) QueueCreate(ctx context.Context, actor, key string, req CreateRequest) (Receipt, error) {
	if actor == "" || key == "" || req.TemplateRevisionID == "" || req.TargetClient == "" || !loginPattern.MatchString(req.Login) || req.Login == "master_user" ||
		!validDisplayName(req.DisplayName) {
		return Receipt{}, errors.New("invalid user creation request")
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	receipt, err := r.stageCreate(ctx, tx, actor, key, req)
	if err != nil {
		return Receipt{}, err
	}
	if err = tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}

func (r *Registry) stageCreate(ctx context.Context, tx *sql.Tx, actor, key string, req CreateRequest) (Receipt, error) {
	encoded, err := json.Marshal([]string{"user.create", req.Login, req.DisplayName, req.TemplateRevisionID, req.TargetClient})
	if err != nil {
		return Receipt{}, err
	}
	hash := digest(encoded)
	var result Receipt
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT id,target_id,request_hash FROM operations WHERE actor_id=? AND idempotency_key=?", actor, key).Scan(&result.OperationID, &result.UserID, &previous)
	if err == nil {
		if hash != previous {
			return Receipt{}, ErrIdempotencyConflict
		}
		return result, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, err
	}
	var approved int
	if err = tx.QueryRowContext(ctx, "SELECT count(*) FROM template_revisions v JOIN profile_templates t ON t.id=v.template_id WHERE v.id=? AND v.status='approved' AND t.enabled=1", req.TemplateRevisionID).Scan(&approved); err != nil {
		return Receipt{}, err
	}
	if approved != 1 {
		return Receipt{}, errors.New("template revision unavailable")
	}
	result = Receipt{id(), id()}
	secretID := id()
	entropy := make([]byte, 32)
	rand.Read(entropy)
	password := base64.RawURLEncoding.AppendEncode(nil, entropy)
	clear(entropy)
	defer clear(password)
	nonce, ciphertext, err := r.vault.Encrypt(vault.Binding{UserID: result.UserID, SecretVersion: 1, KeyVersion: uint64(r.keyVersion)}, password)
	if err != nil {
		return Receipt{}, err
	}
	stamp := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err = tx.ExecContext(ctx, "INSERT INTO users(id,login,display_name,status,created_at,updated_at) VALUES(?,?,?,'provisioning',?,?)", result.UserID, req.Login, req.DisplayName, stamp, stamp); err != nil {
		return Receipt{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) VALUES(?,?,1,?,?,?,?,?)", secretID, result.UserID, vault.Algorithm, nonce, ciphertext, r.keyVersion, stamp); err != nil {
		return Receipt{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO user_current_credentials VALUES(?,?,?)", result.UserID, secretID, stamp); err != nil {
		return Receipt{}, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO user_profiles(id,user_id,template_revision_id,target_client) VALUES(?,?,?,?)", id(), result.UserID, req.TemplateRevisionID, req.TargetClient); err != nil {
		return Receipt{}, err
	}
	_, err = tx.ExecContext(ctx, "INSERT INTO operations(id,actor_id,kind,target_type,target_id,status,idempotency_key,request_hash,correlation_id,created_at) VALUES(?,?,'user.create','user',?,'queued',?,?,?,?)", result.OperationID, actor, result.UserID, key, hash, result.OperationID, stamp)
	return result, err
}

// loadCredential is internal to the storage/worker path; no public API returns raw passwords.
func (r *Registry) loadCredential(ctx context.Context, userID string) (vault.PlainSecret, error) {
	var version, keyVersion uint64
	var nonce, ciphertext []byte
	err := r.db.QueryRowContext(ctx, "SELECT c.secret_version,c.key_version,c.nonce,c.ciphertext FROM user_current_credentials u JOIN credentials c ON c.id=u.credential_id AND c.user_id=u.user_id JOIN users a ON a.id=u.user_id WHERE u.user_id=? AND c.revoked_at IS NULL AND a.status IN ('provisioning','active')", userID).Scan(&version, &keyVersion, &nonce, &ciphertext)
	if err != nil {
		return nil, err
	}
	if keyVersion != uint64(r.keyVersion) {
		return nil, errors.New("required credential key version unavailable")
	}
	return r.vault.Decrypt(vault.Binding{UserID: userID, SecretVersion: version, KeyVersion: keyVersion}, nonce, ciphertext)
}
