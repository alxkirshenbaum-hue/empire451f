//go:build linux

package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"syscall"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// InstallationSnapshot is plaintext DB staging and file observations only.
// Managed file contents have not been copied; this is not a complete backup.
type InstallationSnapshot struct {
	Capture    storage.SnapshotCapture
	OwnerRun   string
	Generation int64
	Files      map[string]string
}

type ownedObservation struct {
	generation int64
	files      map[string]string
	info       map[string]os.FileInfo
	total      int64
	bounded    bool
}

func captureInstallationSnapshot(state, config, lockPath, panel, run, directory, ownID string) (InstallationSnapshot, error) {
	var result InstallationSnapshot
	_, err := withOwnedInstallation(state, config, lockPath, panel, run, func(ctx context.Context, registry *storage.Registry) (_ storage.Receipt, resultErr error) {
		var receipt storage.Receipt
		if err := snapshotIntents(state); err != nil {
			return receipt, err
		}
		before, err := observeOwnedFiles(state, config, run, true)
		if err != nil {
			return receipt, err
		}
		keyPath := filepath.Join(panel, "vault.key")
		key, err := before.read(keyPath, 32, true)
		if err != nil {
			return receipt, err
		}
		v, err := vault.New(key)
		clear(key)
		if err != nil {
			return receipt, err
		}
		capture, err := registry.CaptureOwnedSnapshot(ctx, directory, ownID, run, v)
		if err != nil {
			return receipt, err
		}
		accepted := false
		defer func() {
			if !accepted {
				resultErr = errors.Join(resultErr, os.RemoveAll(filepath.Dir(capture.Path)))
			}
		}()
		after, err := observeOwnedFiles(state, config, run, true)
		if err != nil {
			return receipt, err
		}
		_, err = after.read(keyPath, 32, false)
		if err != nil {
			return receipt, err
		}
		if err = snapshotIntents(state); err != nil {
			return receipt, err
		}
		if before.generation != after.generation || !reflect.DeepEqual(before.files, after.files) {
			return receipt, storage.ErrLegacyDrift
		}
		for path, info := range before.info {
			next := after.info[path]
			if next == nil || !os.SameFile(info, next) || info.Size() != next.Size() || info.ModTime() != next.ModTime() {
				return receipt, storage.ErrLegacyDrift
			}
		}
		result = InstallationSnapshot{Capture: capture, OwnerRun: run, Generation: before.generation, Files: before.files}
		accepted = true
		return receipt, nil
	})
	if err != nil {
		return InstallationSnapshot{}, err
	}
	return result, nil
}

func observeOwnedFiles(state, config, run string, bounded bool) (*ownedObservation, error) {
	o := &ownedObservation{files: map[string]string{}, info: map[string]os.FileInfo{}, bounded: bounded}
	data, err := o.read(filepath.Join(state, "manifest.json"), 1024*1024, true)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	var manifest struct {
		Generation int64             `json:"panel_generation"`
		Run        string            `json:"panel_run_id"`
		Hash       string            `json:"panel_auth_hash"`
		Files      map[string]string `json:"files"`
		Config     struct {
			ID string `json:"id"`
		} `json:"config"`
	}
	if json.Unmarshal(data, &manifest) != nil || manifest.Files == nil || manifest.Generation < 1 || manifest.Run != run || manifest.Config.ID != filepath.Base(state) {
		return nil, storage.ErrLegacyConflict
	}
	auth := filepath.Join(config, filepath.Base(state), "auth.caddy")
	if _, ok := manifest.Files[auth]; ok {
		return nil, storage.ErrLegacyConflict
	}
	if len(manifest.Files) > 4093 {
		return nil, storage.ErrSnapshotState
	}
	if _, err = o.read(auth, storage.SnapshotMaxBytes, false); err != nil {
		return nil, err
	}
	if o.files[auth] != manifest.Hash {
		return nil, storage.ErrLegacyDrift
	}
	for path, expected := range manifest.Files {
		if _, err = o.read(path, storage.SnapshotMaxBytes, false); err != nil {
			return nil, errors.Join(storage.ErrLegacyDrift, err)
		}
		if o.files[path] != expected {
			return nil, storage.ErrLegacyDrift
		}
	}
	o.generation = manifest.Generation
	return o, nil
}

// The caller keeps trusted parent paths immutable. Reject symlink components,
// nonregular files and multiply linked files, then hash bounded streaming reads.
func (o *ownedObservation) read(path string, limit int64, retain bool) ([]byte, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(o.files) >= 4096 {
		return nil, storage.ErrSnapshotState
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return nil, storage.ErrSnapshotState
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || info.Size() > limit || o.bounded && info.Size() > storage.SnapshotMaxBytes-o.total {
		return nil, storage.ErrSnapshotState
	}
	h := sha256.New()
	var content []byte
	reader := io.LimitReader(f, limit+1)
	if retain {
		content, err = io.ReadAll(reader)
		if err == nil {
			_, err = h.Write(content)
		}
	} else {
		var n int64
		n, err = io.Copy(h, reader)
		if n > limit {
			err = storage.ErrSnapshotState
		}
	}
	if err != nil {
		clear(content)
		return nil, err
	}
	next, err := f.Stat()
	if err != nil || next.Size() != info.Size() || next.ModTime() != info.ModTime() || int64(len(content)) > limit {
		clear(content)
		return nil, storage.ErrLegacyDrift
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) {
		clear(content)
		return nil, storage.ErrLegacyDrift
	}
	o.total += next.Size()
	if o.bounded && o.total > storage.SnapshotMaxBytes {
		clear(content)
		return nil, storage.ErrSnapshotState
	}
	o.files[path] = hex.EncodeToString(h.Sum(nil))
	o.info[path] = next
	return content, nil
}

func snapshotIntents(state string) error {
	for _, name := range []string{"pending.json", "user-rollback.json", "return-intent.json", "panel-auth-pending.json", "prepared.json"} {
		if _, err := os.Lstat(filepath.Join(state, name)); !errors.Is(err, os.ErrNotExist) {
			return storage.ErrSnapshotState
		}
	}
	root := filepath.Join(state, "panel-operations")
	info, err := os.Lstat(root)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return storage.ErrSnapshotState
	}
	count := 0
	var inspect func(string) error
	inspect = func(directory string) error {
		resolved, err := filepath.EvalSymlinks(directory)
		if err != nil || resolved != directory {
			return storage.ErrSnapshotState
		}
		fd, err := syscall.Open(directory, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
		if err != nil {
			return err
		}
		f := os.NewFile(uintptr(fd), directory)
		entries, readErr := f.ReadDir(4097 - count)
		closeErr := f.Close()
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		count += len(entries)
		if count > 4096 {
			return storage.ErrSnapshotState
		}
		for _, entry := range entries {
			if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return storage.ErrSnapshotState
			}
			if err := inspect(filepath.Join(directory, entry.Name())); err != nil {
				return err
			}
		}
		return nil
	}
	return inspect(root)
}
