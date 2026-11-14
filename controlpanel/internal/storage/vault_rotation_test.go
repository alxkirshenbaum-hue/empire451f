package storage

import (
	"bytes"
	"context"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"math"
	"os"
	"testing"
)

func TestVaultRotationCopyPreservesCredentialsAndSource(t *testing.T) {
	path, r, u := snapshotFixture(t)
	before, e := r.OpenForPurpose(ctx, u.UserID, RenderProfile)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(before)
	next, _ := vault.New(bytes.Repeat([]byte{92}, 32))
	stage := t.TempDir()
	os.Chmod(stage, 0700)
	captured, e := r.RotateVaultCopy(ctx, stage, "", next)
	if e != nil {
		t.Fatal(e)
	}
	rotated, e := Open(ctx, captured.Path, next, 2)
	if e != nil {
		t.Fatal(e)
	}
	defer rotated.Close()
	after, e := rotated.OpenForPurpose(ctx, u.UserID, RenderProfile)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("credential changed", e)
	}
	clear(after)
	if _, e = Open(ctx, captured.Path, r.vault, 2); !errors.Is(e, ErrVaultKey) {
		t.Fatal("old key accepted by candidate", e)
	}
	if _, e = Open(ctx, path, next, 1); !errors.Is(e, ErrVaultKey) {
		t.Fatal("new key accepted by source", e)
	}
	source, e := r.OpenForPurpose(ctx, u.UserID, RenderProfile)
	if e != nil || !bytes.Equal(source, before) {
		t.Fatal("source changed", e)
	}
	clear(source)
	if _, e = r.InspectSnapshot(ctx, ""); e != nil {
		t.Fatal(e)
	}
}
func TestVaultRotationCopyCancellationCleansOnlyCandidate(t *testing.T) {
	_, r, _ := snapshotFixture(t)
	stage := t.TempDir()
	os.Chmod(stage, 0700)
	sentry := stage + "/sentry"
	os.WriteFile(sentry, []byte("keep"), 0600)
	next, _ := vault.New(bytes.Repeat([]byte{93}, 32))
	c, cancel := context.WithCancel(ctx)
	cancel()
	if _, e := r.RotateVaultCopy(c, stage, "", next); !errors.Is(e, context.Canceled) {
		t.Fatal(e)
	}
	entries, _ := os.ReadDir(stage)
	if len(entries) != 1 || entries[0].Name() != "sentry" {
		t.Fatal("unexpected cleanup")
	}
}

func TestVaultRotationSequentialVersionsAndReadonlyInspector(t *testing.T) {
	path, r, u := snapshotFixture(t)
	// Preserve a non-current revoked historical credential as well as current rows.
	historical := vault.PlainSecret("historical-synthetic")
	nonce, ciphertext, e := r.vault.Encrypt(vault.Binding{UserID: u.UserID, SecretVersion: 7, KeyVersion: 1}, historical)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.db.Exec("INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at,revoked_at) VALUES(?,?,7,?,?,?,?,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)", "historical", u.UserID, vault.Algorithm, nonce, ciphertext, 1); e != nil {
		t.Fatal(e)
	}
	if _, e := r.db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); e != nil {
		t.Fatal(e)
	}
	sourceBefore, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	sourceInfo, _ := os.Stat(path)
	original := r
	for version := int64(2); version <= 3; version++ {
		next, _ := vault.New(bytes.Repeat([]byte{byte(90 + version)}, 32))
		captured, e := r.RotateVaultCopy(ctx, captureParent(t), "", next)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = InspectCapturedSnapshot(ctx, captured.Path, next, "", ""); e != nil {
			t.Fatalf("readonly v%d: %v", version, e)
		}
		if _, e = InspectCapturedSnapshot(ctx, captured.Path, r.vault, "", ""); !errors.Is(e, ErrVaultKey) {
			t.Fatalf("wrong pair: %v", e)
		}
		newer, e := Open(ctx, captured.Path, next, version)
		if e != nil {
			t.Fatal(e)
		}
		defer newer.Close()
		before, e := r.OpenForPurpose(ctx, u.UserID, RenderProfile)
		if e != nil {
			t.Fatal(e)
		}
		after, e := newer.OpenForPurpose(ctx, u.UserID, RenderProfile)
		if e != nil || !bytes.Equal(before, after) {
			t.Fatal("credential changed", e)
		}
		clear(before)
		clear(after)
		var hnonce, hcipher []byte
		var keyVersion int64
		var revoked string
		if e = newer.db.QueryRow("SELECT nonce,ciphertext,key_version,revoked_at FROM credentials WHERE id='historical'").Scan(&hnonce, &hcipher, &keyVersion, &revoked); e != nil {
			t.Fatal(e)
		}
		plain, e := next.Decrypt(vault.Binding{UserID: u.UserID, SecretVersion: 7, KeyVersion: uint64(version)}, hnonce, hcipher)
		if e != nil || keyVersion != version || revoked == "" || !bytes.Equal(plain, historical) {
			t.Fatal("history changed", e)
		}
		clear(plain)
		r = newer
	}
	sourceAfter, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	info, _ := os.Stat(path)
	if !bytes.Equal(sourceBefore, sourceAfter) || !os.SameFile(sourceInfo, info) {
		t.Fatal("source bytes or inode changed")
	}
	if _, e = original.InspectSnapshot(ctx, ""); e != nil {
		t.Fatal(e)
	}
}

func TestVaultRotationRejectsSameMaterialAndOverflowBeforeCapture(t *testing.T) {
	_, r, _ := snapshotFixture(t)
	// A distinct object with identical key material must also be refused.
	same := *r.vault
	stage := captureParent(t)
	if _, e := r.RotateVaultCopy(ctx, stage, "", &same); !errors.Is(e, ErrVaultKey) {
		t.Fatal(e)
	}
	r.keyVersion = math.MaxInt64
	next, _ := vault.New(bytes.Repeat([]byte{99}, 32))
	if _, e := r.RotateVaultCopy(ctx, stage, "", next); !errors.Is(e, ErrVaultKey) {
		t.Fatal(e)
	}
	entries, e := os.ReadDir(stage)
	if e != nil || len(entries) != 0 {
		t.Fatal("candidate allocated for refused rotation", e)
	}
}

func TestVaultRotationPartialWriteFailureCleansCandidate(t *testing.T) {
	_, r, _ := snapshotFixture(t)
	// The second row update fails after the first succeeds inside the candidate
	// transaction. The original trigger and data are never updated.
	_, e := r.db.Exec(`CREATE TRIGGER rotation_fault BEFORE UPDATE OF key_version ON credentials WHEN NEW.key_version>1 AND EXISTS(SELECT 1 FROM credentials WHERE key_version>1) BEGIN SELECT RAISE(ABORT,'injected rotation failure'); END`)
	if e != nil {
		t.Fatal(e)
	}
	stage := captureParent(t)
	next, _ := vault.New(bytes.Repeat([]byte{98}, 32))
	if _, e = r.RotateVaultCopy(ctx, stage, "", next); e == nil {
		t.Fatal("fault not observed")
	}
	entries, e := os.ReadDir(stage)
	if e != nil || len(entries) != 0 {
		t.Fatal("candidate leaked", e)
	}
	if _, e = r.InspectSnapshot(ctx, ""); e != nil {
		t.Fatal("source damaged", e)
	}
}
