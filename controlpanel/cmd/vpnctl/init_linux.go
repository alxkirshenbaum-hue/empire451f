//go:build linux

package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func initializeRegistry(args []string, out, stderr io.Writer) int {
	flags := flag.NewFlagSet("registry init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	installation := flags.String("installation", "", "Installation ID")
	source := flags.String("sfa-template", "", "Reviewed root-owned template")
	approved := flags.String("approve-sha256", "", "Explicit reviewed template digest")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !installationID.MatchString(*installation) || !regexp.MustCompile("^[0-9a-f]{64}$").MatchString(*approved) {
		fmt.Fprintln(stderr, "Expected installation, SFA template and approved SHA-256")
		return 2
	}
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "Run as root on the entry")
		return 3
	}
	fail := func() int {
		fmt.Fprintln(stderr, "Registry initialization refused; preserve existing keys and inspect protected state")
		return 5
	}
	if rootFile(*source, false) != nil {
		return fail()
	}
	body, err := os.ReadFile(*source)
	if err != nil {
		return fail()
	}
	sum := sha256.Sum256(body)
	if fmt.Sprintf("%x", sum) != *approved {
		return fail()
	}
	lock, err := installationLock("/run/lock/empire-vpn.lock")
	if err != nil {
		return fail()
	}
	defer lock.Close()
	panel := "/var/lib/vpn-control"
	keyPath := filepath.Join(panel, "vault.key")
	dbPath := filepath.Join(panel, "state.db")
	if err = os.Mkdir(panel, 0700); err != nil && !os.IsExist(err) {
		return fail()
	}
	info, err := os.Lstat(panel)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return fail()
	}
	data, err := os.ReadFile(filepath.Join("/var/lib/empire-vpn", *installation, "manifest.json"))
	if err != nil {
		return fail()
	}
	var meta struct {
		Config struct {
			ID string `json:"id"`
		} `json:"config"`
		Generation *int64 `json:"panel_generation"`
	}
	if json.Unmarshal(data, &meta) != nil || meta.Config.ID != *installation {
		return fail()
	}
	if _, e := os.Lstat(dbPath); os.IsNotExist(e) && meta.Generation != nil {
		return fail()
	}
	info, err = os.Lstat(keyPath)
	if os.IsNotExist(err) {
		if _, e := os.Lstat(dbPath); !os.IsNotExist(e) {
			return fail()
		}
		key := make([]byte, 32)
		if _, err = rand.Read(key); err != nil {
			return fail()
		}
		file, e := os.OpenFile(keyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			clear(key)
			return fail()
		}
		_, err = file.Write(key)
		clear(key)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil || closeErr != nil {
			return fail()
		}
		dir, e := os.Open(panel)
		if e != nil {
			return fail()
		}
		err = dir.Sync()
		closeErr = dir.Close()
		if err != nil || closeErr != nil {
			return fail()
		}
		info, err = os.Lstat(keyPath)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() != 32 {
		return fail()
	}
	key, err := os.ReadFile(keyPath)
	if err != nil {
		return fail()
	}
	cipher, err := vault.New(key)
	clear(key)
	if err != nil {
		return fail()
	}
	registry, err := storage.Open(context.Background(), dbPath, cipher, 1)
	if err != nil {
		return fail()
	}
	defer registry.Close()
	revision, err := registry.InstallInitialSFA(context.Background(), body, *approved)
	if err != nil {
		return fail()
	}
	if json.NewEncoder(out).Encode(map[string]string{"status": "initialized", "template_revision_id": revision}) != nil {
		return 9
	}
	return 0
}
