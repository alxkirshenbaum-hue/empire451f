//go:build linux

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"syscall"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

type VerifiedManagedArchive struct {
	Root           string                     `json:"-"`
	ManifestSHA256 string                     `json:"manifest_sha256"`
	Inspection     storage.SnapshotInspection `json:"inspection"`
	Manifest       ManagedArchiveManifest     `json:"manifest"`
}

// RestoreSourceRoots is trusted caller policy, never read from the archive.
type RestoreSourceRoots struct{ PanelRoot, StateRoot, ConfigRoot string }

func (r RestoreSourceRoots) valid() bool {
	roots := []string{r.PanelRoot, r.StateRoot, r.ConfigRoot}
	for i, p := range roots {
		if !safeBackupOriginal(p) {
			return false
		}
		for j, q := range roots {
			if i != j && (p == q || strings.HasPrefix(p, q+"/")) {
				return false
			}
		}
	}
	return true
}
func (r RestoreSourceRoots) permits(path string) bool {
	if path == filepath.Join(r.PanelRoot, "state.db") || path == filepath.Join(r.PanelRoot, "vault.key") {
		return true
	}
	if filepath.Dir(path) == r.StateRoot {
		n := filepath.Base(path)
		return n == "manifest.json" || n == "clients.json" || n == "master_user.sfa.json" || (strings.HasPrefix(n, "vpn-") && strings.HasSuffix(n, ".json"))
	}
	return strings.HasPrefix(path, r.ConfigRoot+"/")
}

var backupBlobName = regexp.MustCompile(`^blobs/[0-9]{4}$`)
var backupDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// verifyManagedArchive accepts only a plaintext artifact already authenticated
// off-node by GCM and the authenticated ciphertext digest. It never opens live
// installation paths: original absolute paths are metadata mapped below root.
func verifyManagedArchive(ctx context.Context, archive, staging, expectedManifestSHA, expectedOwnerRun, ownID string, roots RestoreSourceRoots) (out VerifiedManagedArchive, resultErr error) {
	if !roots.valid() || !backupDigest.MatchString(expectedManifestSHA) || expectedOwnerRun == "" {
		return out, storage.ErrSnapshotState
	}
	if !filepath.IsAbs(staging) || filepath.Clean(staging) != staging {
		return out, storage.ErrSnapshotState
	}
	parent := filepath.Dir(staging)
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil || resolved != parent {
		return out, storage.ErrSnapshotState
	}
	pi, err := os.Stat(parent)
	if err != nil || !pi.IsDir() || pi.Mode().Perm()&0077 != 0 {
		return out, storage.ErrSnapshotState
	}
	if err = os.Mkdir(staging, 0700); err != nil {
		return out, err
	}
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, os.RemoveAll(staging))
			out = VerifiedManagedArchive{}
		}
	}()
	// Bound the descriptor and reject links before parsing any untrusted archive.
	resolved, err = filepath.EvalSymlinks(archive)
	if err != nil || resolved != archive {
		return out, storage.ErrSnapshotState
	}
	fd, err := syscall.Open(archive, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return out, err
	}
	f := os.NewFile(uintptr(fd), archive)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return out, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || info.Size() > storage.SnapshotMaxBytes {
		return out, storage.ErrSnapshotState
	}
	tr := tar.NewReader(io.LimitReader(f, storage.SnapshotMaxBytes+1))
	temp := filepath.Join(staging, ".blobs")
	if err = os.Mkdir(temp, 0700); err != nil {
		return out, err
	}
	seen := map[string]ManagedArchiveMember{}
	var raw []byte
	var logical int64
	for count := 0; ; count++ {
		if err = ctx.Err(); err != nil {
			return out, err
		}
		hdr, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, storage.ErrSnapshotState
		}
		if count > 4096 || hdr.Typeflag != tar.TypeReg || hdr.Format != tar.FormatUSTAR || len(hdr.PAXRecords) != 0 || len(hdr.Xattrs) != 0 || hdr.Linkname != "" || hdr.Size < 0 || hdr.Size > storage.SnapshotMaxBytes-logical || hdr.Mode != 0600 || hdr.Uid != 0 || hdr.Gid != 0 {
			return out, storage.ErrSnapshotState
		}
		logical += hdr.Size
		if hdr.Name == "manifest.json" {
			if raw != nil || hdr.Size > 1024*1024 {
				return out, storage.ErrSnapshotState
			}
			raw, e = io.ReadAll(tr)
			if e != nil {
				return out, e
			}
			continue
		}
		if !backupBlobName.MatchString(hdr.Name) {
			return out, storage.ErrSnapshotState
		}
		if _, ok := seen[hdr.Name]; ok {
			return out, storage.ErrSnapshotState
		}
		target := filepath.Join(temp, filepath.Base(hdr.Name))
		file, e := os.OpenFile(target, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if e != nil {
			return out, e
		}
		hash := sha256.New()
		n, e := copyBackupContext(ctx, io.MultiWriter(file, hash), tr, hdr.Size)
		closeErr := file.Close()
		if e != nil || closeErr != nil || n != hdr.Size {
			return out, storage.ErrSnapshotState
		}
		seen[hdr.Name] = ManagedArchiveMember{Blob: hdr.Name, SHA256: hex.EncodeToString(hash.Sum(nil)), Size: n}
	}
	// Go tar stops at its zero terminator; reject hidden nonzero trailing members.
	rest := make([]byte, 64*1024)
	tailBytes, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return out, err
	}
	for {
		n, e := f.Read(rest)
		tailBytes += int64(n)
		if tailBytes > storage.SnapshotMaxBytes {
			return out, storage.ErrSnapshotState
		}
		for _, b := range rest[:n] {
			if b != 0 {
				return out, storage.ErrSnapshotState
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return out, e
		}
	}
	if raw == nil || fmt.Sprintf("%x", sha256.Sum256(raw)) != expectedManifestSHA {
		return out, storage.ErrSnapshotState
	}
	var manifest ManagedArchiveManifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&manifest) != nil || manifest.Format != "vpn-control-managed-backup-v1" || manifest.OwnerRun != expectedOwnerRun || manifest.OwnOperation != ownID || manifest.Generation < 1 || len(manifest.Members) != len(seen) || len(manifest.Members) > 4096 {
		return out, storage.ErrSnapshotState
	}
	if !reflect.DeepEqual(manifest.Excluded, []string{"external:ssh-host-and-authorized-keys", "external:tls-certificates-and-private-keys", "external:acme-account-state"}) {
		return out, storage.ErrSnapshotState
	}
	paths := map[string]ManagedArchiveMember{}
	blobs := map[string]bool{}
	for _, m := range manifest.Members {
		actual, ok := seen[m.Blob]
		if !ok || blobs[m.Blob] || !safeBackupOriginal(m.Path) || !roots.permits(m.Path) || !backupDigest.MatchString(m.SHA256) || m.SHA256 != actual.SHA256 || m.Size != actual.Size || m.Mode&^uint32(0777) != 0 || len(m.Xattrs) != 0 || m.XattrsSHA256 != fmt.Sprintf("%x", sha256.Sum256([]byte("{}"))) {
			return out, storage.ErrSnapshotState
		}
		if _, ok := paths[m.Path]; ok {
			return out, storage.ErrSnapshotState
		}
		paths[m.Path] = m
		blobs[m.Blob] = true
	}
	if manifest.RegistryPath != filepath.Join(roots.PanelRoot, "state.db") {
		return out, storage.ErrSnapshotState
	}
	if _, ok := paths[filepath.Join(roots.StateRoot, "manifest.json")]; !ok {
		return out, storage.ErrSnapshotState
	}
	db, ok := paths[manifest.RegistryPath]
	if !ok || db.SHA256 != manifest.Capture.SHA256 || db.Size != manifest.Capture.Bytes {
		return out, storage.ErrSnapshotState
	}
	vaultPath := filepath.Join(filepath.Dir(manifest.RegistryPath), "vault.key")
	keyMember, ok := paths[vaultPath]
	if !ok || keyMember.Size != 32 || manifest.Observations[vaultPath] != keyMember.SHA256 {
		return out, storage.ErrSnapshotState
	}
	for path, hash := range manifest.Observations {
		m, ok := paths[path]
		if !ok || hash != m.SHA256 {
			return out, storage.ErrSnapshotState
		}
	}
	if err = validateBackupCoverage(manifest, paths, temp); err != nil {
		return out, err
	}
	key, err := os.ReadFile(filepath.Join(temp, filepath.Base(keyMember.Blob)))
	if err != nil {
		return out, err
	}
	v, err := vault.New(key)
	clear(key)
	if err != nil {
		return out, err
	}
	inspection, err := storage.InspectCapturedSnapshot(ctx, filepath.Join(temp, filepath.Base(db.Blob)), v, expectedOwnerRun, ownID)
	if err != nil {
		return out, err
	}
	if inspection != manifest.Capture.Inspection {
		return out, storage.ErrSnapshotState
	}
	for _, m := range manifest.Members {
		target := filepath.Join(staging, strings.TrimPrefix(m.Path, "/"))
		if err = os.MkdirAll(filepath.Dir(target), 0700); err != nil {
			return out, err
		}
		if _, err = os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			return out, storage.ErrSnapshotState
		}
		if err = os.Rename(filepath.Join(temp, filepath.Base(m.Blob)), target); err != nil {
			return out, err
		}
		// Keep restored files private. Original ownership/modes remain metadata until
		// an explicitly approved offline runtime preparation applies that policy.
	}
	if err = os.Remove(temp); err != nil {
		return out, err
	}
	accepted = true
	return VerifiedManagedArchive{Root: staging, ManifestSHA256: expectedManifestSHA, Inspection: inspection, Manifest: manifest}, nil
}

func safeBackupOriginal(path string) bool {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.Contains(path, "\\") || strings.ContainsAny(path, "\x00\r\n") {
		return false
	}
	for _, prefix := range []string{"/root", "/home", "/etc/ssh", "/etc/ssl", "/etc/letsencrypt", "/proc", "/sys", "/dev", "/run"} {
		if path == prefix || strings.HasPrefix(path, prefix+"/") {
			return false
		}
	}
	return true
}

func copyBackupContext(ctx context.Context, w io.Writer, r io.Reader, limit int64) (int64, error) {
	var total int64
	buf := make([]byte, 64*1024)
	for {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		n, e := r.Read(buf)
		total += int64(n)
		if total > limit {
			return total, storage.ErrSnapshotState
		}
		if n > 0 {
			if _, err := w.Write(buf[:n]); err != nil {
				return total, err
			}
		}
		if e == io.EOF {
			return total, nil
		}
		if e != nil {
			return total, e
		}
	}
}

func validateBackupCoverage(manifest ManagedArchiveManifest, paths map[string]ManagedArchiveMember, temp string) error {
	var stateManifest ManagedArchiveMember
	found := false
	for path, m := range paths {
		if filepath.Base(path) == "manifest.json" {
			if found {
				return storage.ErrSnapshotState
			}
			stateManifest = m
			found = true
		}
	}
	if !found || stateManifest.Size > 1024*1024 {
		return storage.ErrSnapshotState
	}
	raw, err := os.ReadFile(filepath.Join(temp, filepath.Base(stateManifest.Blob)))
	if err != nil {
		return err
	}
	var legacy struct {
		Generation int64             `json:"panel_generation"`
		Run        string            `json:"panel_run_id"`
		Hash       string            `json:"panel_auth_hash"`
		Files      map[string]string `json:"files"`
		Config     struct {
			ID string `json:"id"`
		} `json:"config"`
	}
	if json.Unmarshal(raw, &legacy) != nil || legacy.Generation != manifest.Generation || legacy.Run != manifest.OwnerRun || legacy.Config.ID != filepath.Base(filepath.Dir(stateManifest.Path)) {
		return storage.ErrSnapshotState
	}
	allowed := map[string]bool{stateManifest.Path: true, manifest.RegistryPath: true, filepath.Join(filepath.Dir(manifest.RegistryPath), "vault.key"): true}
	for path, hash := range legacy.Files {
		m, ok := paths[path]
		if !ok || hash != m.SHA256 || manifest.Observations[path] != hash {
			return storage.ErrSnapshotState
		}
		allowed[path] = true
	}
	authFound := false
	for path, m := range paths {
		if filepath.Base(path) == "auth.caddy" && filepath.Base(filepath.Dir(path)) == legacy.Config.ID && m.SHA256 == legacy.Hash && manifest.Observations[path] == m.SHA256 {
			allowed[path] = true
			authFound = true
		}
		if filepath.Dir(path) == filepath.Dir(stateManifest.Path) {
			name := filepath.Base(path)
			if name == "clients.json" || name == "master_user.sfa.json" || (strings.HasPrefix(name, "vpn-") && strings.HasSuffix(name, ".json")) {
				allowed[path] = true
			}
		}
	}
	if !authFound || manifest.Observations[stateManifest.Path] != stateManifest.SHA256 {
		return storage.ErrSnapshotState
	}
	for path := range paths {
		if !allowed[path] {
			return storage.ErrSnapshotState
		}
	}
	return nil
}
