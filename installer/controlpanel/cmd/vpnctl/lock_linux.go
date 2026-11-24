//go:build linux

package main

import (
	"os"
	"syscall"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
)

func installationLock(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		f.Close()
		return nil, storage.ErrLegacyConflict
	}
	if err = syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
