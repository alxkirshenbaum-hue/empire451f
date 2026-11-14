package storage

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"database/sql/driver"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
)

const SnapshotMaxBytes = 32 * 1024 * 1024

type SnapshotCapture struct {
	Path       string             `json:"-"`
	SHA256     string             `json:"sha256"`
	Bytes      int64              `json:"bytes"`
	Inspection SnapshotInspection `json:"inspection"`
}

// CaptureSnapshot creates protected plaintext staging, not an encrypted backup.
// The caller must keep the entire private parent path immutable, hold the
// installation writer, and separately check managed files/prepared intents.
// Path checks reject existing symlinks but do not defend against hostile parent
// replacement. SQLite pins the database view, including WAL, independently of
// the installation writer; no global registry generation or auth freeze exists.
func (r *Registry) CaptureSnapshot(ctx context.Context, directory, ownBackupOperationID string) (out SnapshotCapture, err error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err = ctx.Err(); err != nil {
		return out, err
	}
	parent, err := filepath.Abs(directory)
	if err != nil {
		return out, err
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return out, err
	}
	if resolved != parent {
		return out, errors.New("snapshot parent must not contain symlinks")
	}
	info, err := os.Lstat(parent)
	if err != nil {
		return out, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm()&0077 != 0 {
		return out, errors.New("snapshot parent must be private")
	}
	child, err := os.MkdirTemp(parent, "snapshot-")
	if err != nil {
		return out, err
	}
	accepted := false
	defer func() {
		if !accepted {
			err = errors.Join(err, os.RemoveAll(child))
			out = SnapshotCapture{}
		}
	}()
	if err = os.Chmod(child, 0700); err != nil {
		return out, err
	}
	path := filepath.Join(child, "state.db")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		return out, err
	}
	if err = f.Close(); err != nil {
		return out, err
	}
	source, err := r.db.Conn(ctx)
	if err != nil {
		return out, err
	}
	// A read transaction fixes the cut before sizing; external WAL writers cannot
	// grow or restart this backup beyond the measured page count.
	copyErr := func() (result error) {
		defer func() { result = errors.Join(result, source.Close()) }()
		if _, e := source.ExecContext(ctx, "BEGIN"); e != nil {
			return e
		}
		defer func() {
			if _, e := source.ExecContext(context.Background(), "ROLLBACK"); e != nil {
				result = errors.Join(result, e)
				_ = source.Raw(func(any) error { return driver.ErrBadConn })
			}
		}()
		var pages, pageSize int64
		if e := source.QueryRowContext(ctx, "PRAGMA page_count").Scan(&pages); e != nil {
			return e
		}
		if e := source.QueryRowContext(ctx, "PRAGMA page_size").Scan(&pageSize); e != nil {
			return e
		}
		if pages <= 0 || pageSize <= 0 || pageSize > SnapshotMaxBytes || pages > SnapshotMaxBytes/pageSize {
			return errors.New("snapshot exceeds size limit")
		}
		dest, e := sql.Open("sqlite3", snapshotURI(path)+"?mode=rw&_busy_timeout=0")
		if e != nil {
			return e
		}
		defer func() { result = errors.Join(result, dest.Close()) }()
		dest.SetMaxOpenConns(1)
		dc, e := dest.Conn(ctx)
		if e != nil {
			return e
		}
		defer func() { result = errors.Join(result, dc.Close()) }()
		// Set the destination page size before opening its backup transaction.
		if _, e = dc.ExecContext(ctx, fmt.Sprintf("PRAGMA page_size=%d", pageSize)); e != nil {
			return e
		}
		if _, e = dc.ExecContext(ctx, fmt.Sprintf("PRAGMA max_page_count=%d", SnapshotMaxBytes/pageSize)); e != nil {
			return e
		}
		e = source.Raw(func(rawSource any) error {
			src, ok := rawSource.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("snapshot source is not SQLite")
			}
			return dc.Raw(func(rawDest any) (result error) {
				dst, ok := rawDest.(*sqlite3.SQLiteConn)
				if !ok {
					return errors.New("snapshot destination is not SQLite")
				}
				backup, e := dst.Backup("main", src, "main")
				if e != nil {
					return e
				}
				defer func() { result = errors.Join(result, backup.Finish()) }()
				for {
					if e = ctx.Err(); e != nil {
						return e
					}
					done, e := backup.Step(128)
					if e != nil {
						return e
					}
					if int64(backup.PageCount()) > SnapshotMaxBytes/pageSize {
						return errors.New("snapshot exceeds size limit")
					}
					st, e := os.Lstat(path)
					if e != nil {
						return e
					}
					if !st.Mode().IsRegular() || st.Size() > SnapshotMaxBytes {
						return errors.New("unsafe or oversized snapshot")
					}
					if done {
						return ctx.Err()
					}
					// Step returns false,nil on SQLITE_BUSY/LOCKED; always bound retries.
					timer := time.NewTimer(5 * time.Millisecond)
					select {
					case <-ctx.Done():
						timer.Stop()
						return ctx.Err()
					case <-timer.C:
					}
				}
			})
		})
		if e != nil {
			return e
		}
		// Finish has completed; normalize the copied image to a standalone file.
		var journalMode string
		if e = dc.QueryRowContext(ctx, "PRAGMA journal_mode=DELETE").Scan(&journalMode); e != nil {
			return e
		}
		if journalMode != "delete" {
			return errors.New("snapshot journal mode is not standalone")
		}
		return nil
	}()
	if copyErr != nil {
		return out, copyErr
	}
	for _, suffix := range []string{"-wal", "-shm", "-journal"} {
		if _, e := os.Lstat(path + suffix); !errors.Is(e, os.ErrNotExist) {
			return out, errors.New("snapshot has unexpected sidecars")
		}
	}
	// Inspect the actual copied image with no migrations and no write capability.
	captured, err := sql.Open("sqlite3", snapshotURI(path)+"?mode=ro&_query_only=on&_busy_timeout=0")
	if err != nil {
		return out, err
	}
	captured.SetMaxOpenConns(1)
	inspection, inspectErr := (&Registry{db: captured, vault: r.vault, keyVersion: r.keyVersion}).InspectSnapshot(ctx, ownBackupOperationID)
	if err = errors.Join(inspectErr, captured.Close()); err != nil {
		return out, err
	}
	f, err = os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return out, err
	}
	hash := sha256.New()
	buf := make([]byte, 64*1024)
	var size int64
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		n, readErr := f.Read(buf)
		size += int64(n)
		if size > SnapshotMaxBytes {
			err = errors.New("snapshot exceeds size limit")
			break
		}
		if n > 0 {
			_, _ = hash.Write(buf[:n])
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			err = readErr
			break
		}
	}
	if err == nil {
		err = f.Sync()
	}
	err = errors.Join(err, f.Close())
	if err != nil {
		return out, err
	}
	for _, dir := range []string{child, parent} {
		if err = snapshotSyncDirectory(dir); err != nil {
			return out, err
		}
	}
	if err = ctx.Err(); err != nil {
		return out, err
	}
	accepted = true
	return SnapshotCapture{Path: path, SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: size, Inspection: inspection}, nil
}

func snapshotURI(path string) string {
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	if runtime.GOOS == "windows" && !strings.HasPrefix(uri.Path, "/") {
		uri.Path = "/" + uri.Path
	}
	return uri.String()
}

func snapshotSyncDirectory(path string) error {
	// Windows does not support fsync on directory handles through os.File.
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
