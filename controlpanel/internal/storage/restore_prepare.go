//go:build linux

package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// RestoreBinding must come from the authenticated archive receipt, never from
// the untrusted captured database. ManifestSHA256 is required when available.
type RestoreBinding struct {
	OwnerRun       string `json:"owner_run"`
	OwnOperationID string `json:"own_operation_id"`
	BackupID       string `json:"backup_id"`
	CipherSHA256   string `json:"cipher_sha256"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
}

// PrepareRestoreCopy normalizes only a NEW private candidate. Caller authenticates
// the archive and keeps all staging ancestors immutable for the entire call.
// No source registry is opened for writing and no migrations are performed.
func PrepareRestoreCopy(ctx context.Context, source, parent string, key *vault.Vault, binding RestoreBinding) (out SnapshotCapture, resultErr error) {
	if !uuidMaintenance.MatchString(binding.OwnerRun) || !uuidMaintenance.MatchString(binding.OwnOperationID) || !uuidMaintenance.MatchString(binding.BackupID) || !hashPattern.MatchString(binding.CipherSHA256) || (binding.ManifestSHA256 != "" && !hashPattern.MatchString(binding.ManifestSHA256)) {
		return out, ErrSnapshotState
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	for _, p := range []string{filepath.Dir(source), parent} {
		resolved, e := filepath.EvalSymlinks(p)
		if e != nil || resolved != p || !filepath.IsAbs(p) {
			return out, ErrSnapshotState
		}
		i, e := os.Stat(p)
		if e != nil {
			return out, e
		}
		s, ok := i.Sys().(*syscall.Stat_t)
		if !ok || !i.IsDir() || i.Mode().Perm()&0077 != 0 || s.Uid != uint32(os.Geteuid()) {
			return out, ErrSnapshotState
		}
	}
	fd, e := syscall.Open(source, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if e != nil {
		return out, e
	}
	src := os.NewFile(uintptr(fd), source)
	defer src.Close()
	before, e := src.Stat()
	if e != nil {
		return out, e
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || !before.Mode().IsRegular() || st.Nlink != 1 || st.Uid != uint32(os.Geteuid()) || before.Mode().Perm()&0077 != 0 || before.Size() > SnapshotMaxBytes {
		return out, ErrSnapshotState
	}
	sourceHash, e := restoreFileHash(src)
	if e != nil {
		return out, e
	}
	if _, e = InspectCapturedSnapshot(ctx, source, key, binding.OwnerRun, binding.OwnOperationID); e != nil {
		return out, e
	}
	child, e := os.MkdirTemp(parent, "restore-")
	if e != nil {
		return out, e
	}
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, os.RemoveAll(child))
			out = SnapshotCapture{}
		}
	}()
	path := filepath.Join(child, "state.db")
	dest, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if e != nil {
		return out, e
	}
	_, e = src.Seek(0, 0)
	if e == nil {
		_, e = io.Copy(dest, io.LimitReader(src, SnapshotMaxBytes+1))
	}
	e = errors.Join(e, dest.Sync(), dest.Close())
	if e != nil {
		return out, e
	}
	after, e := src.Stat()
	current, ce := os.Lstat(source)
	checkHash, he := restoreFileHash(src)
	if e != nil || ce != nil || he != nil || !os.SameFile(before, current) || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || sourceHash != checkHash {
		return out, ErrSnapshotState
	}
	if _, e = InspectCapturedSnapshot(ctx, path, key, binding.OwnerRun, binding.OwnOperationID); e != nil {
		return out, e
	}
	db, e := sql.Open("sqlite3", snapshotURI(path)+"?mode=rw&_journal_mode=DELETE&_foreign_keys=on&_synchronous=FULL&_txlock=immediate")
	if e != nil {
		return out, e
	}
	db.SetMaxOpenConns(1)
	e = func() error {
		tx, e := db.BeginTx(ctx, nil)
		if e != nil {
			return e
		}
		defer tx.Rollback()
		var request string
		e = tx.QueryRowContext(ctx, `SELECT m.request_json FROM operations o JOIN maintenance_intents m ON m.operation_id=o.id WHERE o.id=? AND o.kind='backup.create' AND o.status='running' AND o.target_type='backup' AND o.target_id=? AND m.owner_run=? AND m.backup_id=?`, binding.OwnOperationID, binding.BackupID, binding.OwnerRun, binding.BackupID).Scan(&request)
		if e != nil {
			return ErrSnapshotState
		}
		var q MaintenanceRequest
		if json.Unmarshal([]byte(request), &q) != nil || q.Action != "backup.create" || !validMaintenance(q) {
			return ErrSnapshotState
		}
		var n int
		if e = tx.QueryRowContext(ctx, `SELECT count(*) FROM operations WHERE id<>? AND status NOT IN ('succeeded','failed','cancelled','rolled_back')`, binding.OwnOperationID).Scan(&n); e != nil {
			return e
		}
		if n != 0 {
			return ErrSnapshotState
		}
		if _, e = tx.ExecContext(ctx, "DELETE FROM admin_sessions"); e != nil {
			return e
		}
		res, e := tx.ExecContext(ctx, `UPDATE operations SET status='failed',error_code='RESTORED_INTERRUPTED',finished_at=CURRENT_TIMESTAMP WHERE id=? AND status='running' AND kind='backup.create'`, binding.OwnOperationID)
		if e != nil {
			return e
		}
		if n, e := res.RowsAffected(); e != nil || n != 1 {
			return ErrSnapshotState
		}
		evidence, _ := json.Marshal(binding)
		if _, e = tx.ExecContext(ctx, `INSERT INTO audit_runs(id,script_version,started_at,finished_at,summary) VALUES(?,'restore-copy-v1',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,?)`, id(), string(evidence)); e != nil {
			return e
		}
		return tx.Commit()
	}()
	e = errors.Join(e, db.Close())
	if e != nil {
		return out, e
	}
	out.Inspection, e = InspectCapturedSnapshot(ctx, path, key, binding.OwnerRun, "")
	if e != nil {
		return out, e
	}
	f, e := os.OpenFile(path, os.O_RDWR, 0)
	if e != nil {
		return out, e
	}
	out.SHA256, e = restoreFileHash(f)
	if e == nil {
		e = f.Sync()
	}
	info, se := f.Stat()
	e = errors.Join(e, se, f.Close())
	if e != nil {
		return out, e
	}
	if e = snapshotSyncDirectory(child); e != nil {
		return out, e
	}
	if e = snapshotSyncDirectory(parent); e != nil {
		return out, e
	}
	out.Path = path
	out.Bytes = info.Size()
	accepted = true
	return out, nil
}
func restoreFileHash(f *os.File) (string, error) {
	if _, e := f.Seek(0, 0); e != nil {
		return "", e
	}
	h := sha256.New()
	n, e := io.Copy(h, io.LimitReader(f, SnapshotMaxBytes+1))
	if e != nil {
		return "", e
	}
	if n > SnapshotMaxBytes {
		return "", ErrSnapshotState
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
