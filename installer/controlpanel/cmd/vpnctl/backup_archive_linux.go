//go:build linux

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"golang.org/x/sys/unix"
)

type ManagedArchive struct {
	Path           string `json:"-"`
	SHA256         string `json:"sha256"`
	Bytes          int64  `json:"bytes"`
	ManifestSHA256 string `json:"manifest_sha256"`
	OwnerRun       string `json:"owner_run"`
	Generation     int64  `json:"generation"`
}

type ManagedArchiveMember struct {
	Path         string            `json:"path"`
	Blob         string            `json:"blob"`
	SHA256       string            `json:"sha256"`
	Size         int64             `json:"size"`
	UID          uint32            `json:"uid"`
	GID          uint32            `json:"gid"`
	Mode         uint32            `json:"mode"`
	Xattrs       map[string]string `json:"xattrs"`
	XattrsSHA256 string            `json:"xattrs_sha256"`
}

type ManagedArchiveManifest struct {
	Format       string                  `json:"format"`
	OwnerRun     string                  `json:"owner_run"`
	Generation   int64                   `json:"generation"`
	OwnOperation string                  `json:"own_operation"`
	Capture      storage.SnapshotCapture `json:"capture"`
	RegistryPath string                  `json:"registry_path"`
	Observations map[string]string       `json:"observations"`
	Members      []ManagedArchiveMember  `json:"members"`
	Excluded     []string                `json:"excluded_external_references"`
}

// createInstallationArchive is called only while holding the existing installation
// writer. Parents must remain trusted and immutable. Supported ACLs/xattrs are
// inventoried in bounded manifest metadata. Archive production is not restore verification.
func createInstallationArchive(ctx context.Context, reg *storage.Registry, state, config, panel, run, workdir, ownID string) (out ManagedArchive, resultErr error) {
	extra, err := archiveLegacyObservation(state)
	if err != nil {
		return out, err
	}
	var snapshot InstallationSnapshot
	snapshot, err = captureInstallationSnapshotLocked(ctx, reg, state, config, panel, run, workdir, ownID, func(s InstallationSnapshot) error {
		expected := make(map[string]string)
		for path, hash := range extra.files {
			expected[path] = hash
		}
		for path, hash := range s.Files {
			expected[path] = hash
		}
		expected[s.Capture.Path] = s.Capture.SHA256
		var e error
		out, e = writeManagedArchive(ctx, workdir, expected, ManagedArchiveManifest{
			Format: "vpn-control-managed-backup-v1", OwnerRun: run, Generation: s.Generation,
			OwnOperation: ownID, Capture: s.Capture, RegistryPath: filepath.Join(panel, "state.db"), Observations: s.Files,
			Excluded: []string{"external:ssh-host-and-authorized-keys", "external:tls-certificates-and-private-keys", "external:acme-account-state"},
		})
		if e != nil {
			return e
		}
		after, e := archiveLegacyObservation(state)
		if e != nil || !reflect.DeepEqual(extra.files, after.files) {
			return storage.ErrLegacyDrift
		}
		current, e := observeOwnedFiles(state, config, run, true)
		if e != nil {
			return e
		}
		if _, e = current.read(filepath.Join(panel, "vault.key"), 32, false); e != nil {
			return e
		}
		if !reflect.DeepEqual(s.Files, current.files) || current.generation != s.Generation {
			return storage.ErrLegacyDrift
		}
		return snapshotIntents(state)
	})
	if snapshot.Capture.Path != "" {
		resultErr = os.RemoveAll(filepath.Dir(snapshot.Capture.Path))
	}
	if err != nil || resultErr != nil {
		if out.Path != "" {
			resultErr = errors.Join(resultErr, os.RemoveAll(filepath.Dir(out.Path)))
		}
		return ManagedArchive{}, errors.Join(err, resultErr)
	}
	return out, nil
}

func archiveLegacyObservation(state string) (*ownedObservation, error) {
	o := &ownedObservation{files: map[string]string{}, info: map[string]os.FileInfo{}, bounded: true}
	paths := []string{filepath.Join(state, "clients.json"), filepath.Join(state, "master_user.sfa.json")}
	matches, err := filepath.Glob(filepath.Join(state, "vpn-*.json"))
	if err != nil || len(matches) > 4090 {
		return nil, storage.ErrSnapshotState
	}
	paths = append(paths, matches...)
	for _, path := range paths {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, err
		}
		if _, err := o.read(path, storage.SnapshotMaxBytes, false); err != nil {
			return nil, err
		}
	}
	return o, nil
}

type archiveBoundedWriter struct {
	writer io.Writer
	bytes  int64
}

func (w *archiveBoundedWriter) Write(p []byte) (int, error) {
	if int64(len(p)) > storage.SnapshotMaxBytes-w.bytes {
		return 0, storage.ErrSnapshotState
	}
	n, err := w.writer.Write(p)
	w.bytes += int64(n)
	return n, err
}

func writeManagedArchive(ctx context.Context, workdir string, expected map[string]string, manifest ManagedArchiveManifest) (out ManagedArchive, resultErr error) {
	resolved, err := filepath.EvalSymlinks(workdir)
	if err != nil || resolved != workdir {
		return out, storage.ErrSnapshotState
	}
	info, err := os.Stat(workdir)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return out, storage.ErrSnapshotState
	}
	child, err := os.MkdirTemp(workdir, "managed-archive-")
	if err != nil {
		return out, err
	}
	accepted := false
	defer func() {
		if !accepted {
			resultErr = errors.Join(resultErr, os.RemoveAll(child))
			out = ManagedArchive{}
		}
	}()
	path := filepath.Join(child, "archive.tar")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return out, err
	}
	defer f.Close()
	hash := sha256.New()
	bounded := &archiveBoundedWriter{writer: io.MultiWriter(f, hash)}
	tw := tar.NewWriter(bounded)
	paths := make([]string, 0, len(expected))
	if len(expected) > 4096 {
		return out, storage.ErrSnapshotState
	}
	for p := range expected {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for i, p := range paths {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		member, err := archiveMember(ctx, tw, p, fmt.Sprintf("blobs/%04d", i), expected[p])
		if err != nil {
			return out, err
		}
		if p == manifest.Capture.Path {
			member.Path = manifest.RegistryPath
		}
		manifest.Members = append(manifest.Members, member)
	}
	raw, err := json.Marshal(manifest)
	if err != nil || len(raw) > 1024*1024 {
		return out, storage.ErrSnapshotState
	}
	if err = tw.WriteHeader(&tar.Header{Name: "manifest.json", Mode: 0600, Size: int64(len(raw)), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		return out, err
	}
	if _, err = tw.Write(raw); err != nil {
		return out, err
	}
	if err = tw.Close(); err != nil {
		return out, err
	}
	if err = f.Sync(); err != nil {
		return out, err
	}
	if err = f.Close(); err != nil {
		return out, err
	}
	out = ManagedArchive{Path: path, SHA256: hex.EncodeToString(hash.Sum(nil)), Bytes: bounded.bytes, ManifestSHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), OwnerRun: manifest.OwnerRun, Generation: manifest.Generation}
	accepted = true
	return out, nil
}

func archiveMember(ctx context.Context, tw *tar.Writer, path, blob, expected string) (member ManagedArchiveMember, resultErr error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return member, storage.ErrSnapshotState
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != path {
		return member, storage.ErrSnapshotState
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return member, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return member, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() || st.Nlink != 1 || info.Size() > storage.SnapshotMaxBytes {
		return member, storage.ErrSnapshotState
	}
	attrs, err := readArchiveXattrs(fd, st.Mode&0777)
	if err != nil {
		return member, err
	}
	if err = tw.WriteHeader(&tar.Header{Name: blob, Mode: 0600, Size: info.Size(), Typeflag: tar.TypeReg, Format: tar.FormatUSTAR}); err != nil {
		return member, err
	}
	h := sha256.New()
	buf := make([]byte, 64*1024)
	remaining := info.Size()
	for remaining > 0 {
		if err = ctx.Err(); err != nil {
			return member, err
		}
		count := int64(len(buf))
		if remaining < count {
			count = remaining
		}
		n, e := io.ReadFull(f, buf[:count])
		if e != nil {
			return member, e
		}
		if _, err = io.MultiWriter(tw, h).Write(buf[:n]); err != nil {
			return member, err
		}
		remaining -= int64(n)
	}
	end, err := f.Stat()
	current, e := os.Lstat(path)
	endAttrs, ae := readArchiveXattrs(fd, st.Mode&0777)
	if err != nil || e != nil || ae != nil || !reflect.DeepEqual(attrs, endAttrs) || !os.SameFile(info, current) || !archiveSameMetadata(info, end) || hex.EncodeToString(h.Sum(nil)) != expected {
		return member, storage.ErrLegacyDrift
	}
	return ManagedArchiveMember{Path: path, Blob: blob, SHA256: expected, Size: info.Size(), UID: st.Uid, GID: st.Gid, Mode: st.Mode & 07777, Xattrs: attrs, XattrsSHA256: archiveXattrsDigest(attrs)}, nil
}

func archiveSameMetadata(a, b os.FileInfo) bool {
	x, ok := a.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	y, ok := b.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return x.Dev == y.Dev && x.Ino == y.Ino && x.Size == y.Size && x.Mode == y.Mode && x.Uid == y.Uid && x.Gid == y.Gid && x.Nlink == y.Nlink && x.Mtim == y.Mtim && x.Ctim == y.Ctim
}

// Attributes are manifest metadata, never PAX records. Privileged namespaces and
// directory default ACLs are unsupported. Values are canonical base64, not text.
func archiveXattrsDigest(attrs map[string]string) string {
	raw, _ := json.Marshal(attrs)
	return fmt.Sprintf("%x", sha256.Sum256(raw))
}
func validateArchiveXattrs(attrs map[string]string, mode uint32) error {
	if attrs == nil || len(attrs) > 64 {
		return storage.ErrSnapshotState
	}
	total := 0
	for name, value := range attrs {
		if len(name) > 255 || !(strings.HasPrefix(name, "user.") && len(name) > 5 || name == "system.posix_acl_access") {
			return storage.ErrSnapshotState
		}
		for _, c := range []byte(name) {
			if c < 33 || c > 126 {
				return storage.ErrSnapshotState
			}
		}
		if len(value) > 87384 {
			return storage.ErrSnapshotState
		}
		raw, err := base64.StdEncoding.Strict().DecodeString(value)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != value {
			return storage.ErrSnapshotState
		}
		total += len(name) + len(raw)
		if total > 65536 {
			return storage.ErrSnapshotState
		}
		if name == "system.posix_acl_access" && !validArchiveACL(raw, mode) {
			return storage.ErrSnapshotState
		}
	}
	return nil
}
func validArchiveACL(raw []byte, mode uint32) bool {
	if len(raw) < 28 || (len(raw)-4)%8 != 0 || binary.LittleEndian.Uint32(raw) != 2 {
		return false
	}
	stage := uint16(0)
	bases := map[uint16]uint16{}
	named := false
	lastID := uint32(0)
	haveID := false
	for p := 4; p < len(raw); p += 8 {
		tag := binary.LittleEndian.Uint16(raw[p:])
		perm := binary.LittleEndian.Uint16(raw[p+2:])
		id := binary.LittleEndian.Uint32(raw[p+4:])
		if perm > 7 || !(tag == 1 || tag == 2 || tag == 4 || tag == 8 || tag == 16 || tag == 32) || tag < stage {
			return false
		}
		if tag == 2 || tag == 8 {
			named = true
			if id == 0xffffffff || tag == stage && haveID && id <= lastID {
				return false
			}
			lastID = id
			haveID = true
		} else {
			if id != 0xffffffff {
				return false
			}
			if _, ok := bases[tag]; ok {
				return false
			}
			bases[tag] = perm
			haveID = false
		}
		stage = tag
	}
	for _, tag := range []uint16{1, 4, 32} {
		if _, ok := bases[tag]; !ok {
			return false
		}
	}
	group := bases[4]
	if mask, ok := bases[16]; ok {
		group = mask
	} else if named {
		return false
	}
	return uint32(bases[1]) == mode>>6&7 && uint32(group) == mode>>3&7 && uint32(bases[32]) == mode&7
}
func readArchiveXattrs(fd int, mode uint32) (map[string]string, error) {
	n, err := unix.Flistxattr(fd, nil)
	if err != nil || n > 65536 {
		return nil, storage.ErrSnapshotState
	}
	names := make([]byte, n)
	got, err := unix.Flistxattr(fd, names)
	if err != nil || got != n {
		return nil, storage.ErrLegacyDrift
	}
	attrs := map[string]string{}
	total := 0
	if n > 0 {
		if names[n-1] != 0 {
			return nil, storage.ErrSnapshotState
		}
		for _, name := range strings.Split(string(names[:n-1]), "\x00") {
			if len(attrs) >= 64 {
				return nil, storage.ErrSnapshotState
			}
			size, e := unix.Fgetxattr(fd, name, nil)
			if e != nil || size > 65536-total-len(name) {
				return nil, storage.ErrSnapshotState
			}
			total += size + len(name)
			value := make([]byte, size)
			got, e := unix.Fgetxattr(fd, name, value)
			if e != nil || got != size {
				return nil, storage.ErrLegacyDrift
			}
			attrs[name] = base64.StdEncoding.EncodeToString(value)
		}
	}
	if err := validateArchiveXattrs(attrs, mode); err != nil {
		return nil, err
	}
	return attrs, nil
}
