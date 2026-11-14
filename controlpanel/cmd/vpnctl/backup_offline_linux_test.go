//go:build linux

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOfflineVerifyEncryptedRoundtrip(t *testing.T) {
	archive, root, run := restoreArchiveFixture(t)
	key, e := rsa.GenerateKey(rand.Reader, 2048)
	if e != nil {
		t.Fatal(e)
	}
	pub, e := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if e != nil {
		t.Fatal(e)
	}
	private := filepath.Join(root, "private.pem")
	recipient := filepath.Join(root, "public.pem")
	if e = os.WriteFile(private, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0600); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(recipient, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pub}), 0600); e != nil {
		t.Fatal(e)
	}
	helper, e := filepath.Abs("../../../backup_artifact.py")
	if e != nil {
		t.Fatal(e)
	}
	envelope := filepath.Join(root, "backup.jwe")
	sealed, e := artifactCommand(context.Background(), helper, map[string]string{"action": "seal", "source": archive.Path, "public_key_path": recipient, "output": envelope})
	if e != nil {
		t.Fatal(e)
	}
	args := []string{"backup", "offline-verify", "--envelope", envelope, "--private-key", private, "--cipher-sha256", sealed.SHA256, "--manifest-sha256", archive.ManifestSHA256, "--owner-run", run, "--helper", helper, "--source-panel-root", filepath.Join(root, "panel"), "--source-state-root", filepath.Join(root, "state", "lab"), "--source-config-root", filepath.Join(root, "etc"), "--staging", filepath.Join(root, "checked")}
	var out, stderr bytes.Buffer
	if code := execute(args, &out, &stderr); code != 0 {
		t.Fatalf("code%d: %s", code, stderr.String())
	}
	var report map[string]any
	if e = json.Unmarshal(out.Bytes(), &report); e != nil {
		t.Fatal(e)
	}
	if report["outcome"] != "artifact_check_passed" || report["usable_restore"] != "not_run" || strings.Contains(out.String(), root) || strings.Contains(out.String(), "fixture-master") {
		t.Fatal("unsafe or overstated report")
	}
	out.Reset()
	stderr.Reset()
	if code := execute(args, &out, &stderr); code == 0 {
		t.Fatal("existing staging overwritten")
	}
	args[len(args)-1] = filepath.Join(root, "bad-digest")
	for i, a := range args {
		if a == "--cipher-sha256" {
			args[i+1] = strings.Repeat("0", 64)
		}
	}
	if code := execute(args, &out, &stderr); code == 0 {
		t.Fatal("wrong ciphertext accepted")
	}
	if _, e = os.Stat(args[len(args)-1]); !os.IsNotExist(e) {
		t.Fatal("failed authentication published staging")
	}
	children, e := os.ReadDir(root)
	if e != nil {
		t.Fatal(e)
	}
	for _, entry := range children {
		if strings.HasPrefix(entry.Name(), ".offline-decrypt-") {
			t.Fatal("plaintext staging leaked")
		}
	}
}
