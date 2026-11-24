package storage

import (
	"context"
	"database/sql"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"os"
	"path/filepath"
)

// InspectCapturedSnapshot never migrates or writes an untrusted captured DB.
// The caller owns the entire private immutable staging parent and authenticates
// the encrypted object before extraction. No hostile parent replacement allowed.
func InspectCapturedSnapshot(ctx context.Context, path string, expectedVault *vault.Vault, ownerRun, ownID string) (SnapshotInspection, error) {
	var result SnapshotInspection
	resolved, e := filepath.EvalSymlinks(path)
	if e != nil || resolved != path || expectedVault == nil {
		return result, ErrSnapshotState
	}
	i, e := os.Stat(path)
	if e != nil || !i.Mode().IsRegular() || i.Size() > SnapshotMaxBytes {
		return result, ErrSnapshotState
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, e = os.Lstat(path + suffix); !errors.Is(e, os.ErrNotExist) {
			return result, ErrSnapshotState
		}
	}
	db, e := sql.Open("sqlite3", snapshotURI(path)+"?mode=ro&_query_only=on&_busy_timeout=0")
	if e != nil {
		return result, e
	}
	db.SetMaxOpenConns(1)
	if ownerRun != "" {
		e = requireVerifiedCutover(ctx, db, ownerRun)
	}
	// The version is an untrusted selector, not evidence of authenticity. The
	// canonical inspector authenticates its bound marker and every credential.
	var version int64
	if e == nil {
		e = db.QueryRowContext(ctx, "SELECT key_version FROM vault_identity WHERE singleton=1").Scan(&version)
		if e == nil && version < 1 {
			e = ErrVaultKey
		}
	}
	if e == nil {
		result, e = (&Registry{db: db, vault: expectedVault, keyVersion: version}).InspectSnapshot(ctx, ownID)
	}
	return result, errors.Join(e, db.Close())
}
