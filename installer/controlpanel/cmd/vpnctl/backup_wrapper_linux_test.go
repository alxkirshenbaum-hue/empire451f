//go:build linux

package main

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
)

func TestManagedArchiveWrapperPolicy(t *testing.T) {
	_, root, run := restoreArchiveFixture(t)
	wrapper := filepath.Join(root, "bin", "vpn-wrapper")
	if err := os.MkdirAll(filepath.Dir(wrapper), 0700); err != nil {
		t.Fatal(err)
	}
	payload := []byte("#!/bin/sh\nexit 0\n")
	if err := os.WriteFile(wrapper, payload, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(wrapper, 0755); err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(payload))
	state := filepath.Join(root, "state", "lab")
	config := filepath.Join(root, "etc")
	panel := filepath.Join(root, "panel")
	manifestPath := filepath.Join(state, "manifest.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]any
	if err = json.Unmarshal(raw, &legacy); err != nil {
		t.Fatal(err)
	}
	legacy["files"].(map[string]any)[wrapper] = digest
	raw, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(manifestPath, raw, 0600); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "wrapper-captures")
	if err = os.Mkdir(dest, 0700); err != nil {
		t.Fatal(err)
	}
	var archive ManagedArchive
	_, err = withOwnedInstallation(state, config, filepath.Join(root, "lock"), panel, run, func(ctx context.Context, reg *storage.Registry) (storage.Receipt, error) {
		var e error
		archive, e = createInstallationArchive(ctx, reg, state, config, panel, run, dest, "")
		return storage.Receipt{}, e
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"valid", "absent-policy", "wrong-path", "wrong-hash", "mode", "uid", "gid", "xattrs"} {
		t.Run(scenario, func(t *testing.T) {
			roots := RestoreSourceRoots{PanelRoot: panel, StateRoot: state, ConfigRoot: config, WrapperPath: wrapper, WrapperSHA256: digest}
			path := archive.Path
			expected := archive.ManifestSHA256
			switch scenario {
			case "absent-policy":
				roots.WrapperPath = ""
				roots.WrapperSHA256 = ""
			case "wrong-path":
				roots.WrapperPath = wrapper + "-other"
			case "wrong-hash":
				roots.WrapperSHA256 = fmt.Sprintf("%064d", 0)
			case "mode", "uid", "gid", "xattrs":
				path = rewriteRestoreArchive(t, archive, func(h *tar.Header, b []byte) (*tar.Header, []byte) {
					if h.Name == "manifest.json" {
						var m ManagedArchiveManifest
						if e := json.Unmarshal(b, &m); e != nil {
							t.Fatal(e)
						}
						found := false
						for i := range m.Members {
							if m.Members[i].Path != wrapper {
								continue
							}
							found = true
							a := &m.Members[i]
							switch scenario {
							case "mode":
								a.Mode = 0700
							case "uid":
								a.UID = 65534
							case "gid":
								a.GID = 65534
							case "xattrs":
								a.Xattrs = map[string]string{"user.fixture": "AA=="}
								a.XattrsSHA256 = archiveXattrsDigest(a.Xattrs)
							}
						}
						if !found {
							t.Fatal("wrapper member absent")
						}
						b, _ = json.Marshal(m)
						expected = fmt.Sprintf("%x", sha256.Sum256(b))
					}
					return h, b
				}, false)
			}
			stage := filepath.Join(root, "wrapper-"+scenario)
			out, e := verifyManagedArchive(context.Background(), path, stage, expected, run, "", roots)
			if scenario == "valid" {
				if e != nil {
					t.Fatal(e)
				}
				body, e := os.ReadFile(filepath.Join(out.Root, wrapper[1:]))
				if e != nil || string(body) != string(payload) {
					t.Fatal("trusted wrapper not preserved")
				}
				return
			}
			if e == nil {
				t.Fatal("untrusted wrapper policy accepted")
			}
			if _, e = os.Stat(stage); !os.IsNotExist(e) {
				t.Fatal("rejected wrapper leaked staging")
			}
		})
	}
}
