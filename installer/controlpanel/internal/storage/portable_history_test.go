package storage

import (
	"bytes"
	"os"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestPortablePreservesCredentialHistoryAndDeletedTombstone(t *testing.T) {
	_, source, run := portableSourceFixture(t)
	var uid, oldID, login string
	if e := source.db.QueryRow("SELECT u.id,x.credential_id,u.login FROM users u JOIN user_current_credentials x ON x.user_id=u.id WHERE u.kind='regular' AND u.login NOT IN ('Alex','alex')").Scan(&uid, &oldID, &login); e != nil {
		t.Fatal(e)
	}
	oldSecret, e := portableSecret(t, source, uid)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(oldSecret)
	newSecret := vault.PlainSecret("synthetic deleted credential version two")
	defer clear(newSecret)
	fresh := id()
	nonce, cipher, e := source.vault.Encrypt(vault.Binding{UserID: uid, SecretVersion: 2, KeyVersion: uint64(source.keyVersion)}, newSecret)
	if e != nil {
		t.Fatal(e)
	}
	tx, e := source.db.BeginTx(ctx, nil)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback()
	if _, e = tx.Exec("UPDATE credentials SET revoked_at='2026-11-15T00:00:00Z',rotated_at='2026-11-15T00:00:00Z' WHERE id=?", oldID); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec("INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at,revoked_at) VALUES(?,?,2,?,?,?,?, '2026-11-15T00:00:00Z','2026-11-15T00:00:00Z')", fresh, uid, vault.Algorithm, nonce, cipher, source.keyVersion); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec("UPDATE user_current_credentials SET credential_id=? WHERE user_id=?", fresh, uid); e != nil {
		t.Fatal(e)
	}
	if _, e = tx.Exec("UPDATE users SET status='deleted',deleted_at='2026-11-15T00:00:00Z',row_version=row_version+1 WHERE id=?", uid); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(); e != nil {
		t.Fatal(e)
	}
	captured, e := source.CaptureSnapshot(ctx, captureParent(t), "")
	if e != nil {
		t.Fatal(e)
	}
	before, e := os.ReadFile(captured.Path)
	if e != nil {
		t.Fatal(e)
	}
	dest := portableDestinationFixture(t)
	plan, e := dest.PreviewPortable(ctx, captured.Path, source.vault, run, "")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = dest.ImportPortable(ctx, captured.Path, source.vault, run, "", plan.Hash, true); e != nil {
		t.Fatal(e)
	}
	var gotLogin, status, deleted, current string
	if e = dest.db.QueryRow("SELECT u.login,u.status,u.deleted_at,x.credential_id FROM users u JOIN user_current_credentials x ON x.user_id=u.id WHERE u.id=?", uid).Scan(&gotLogin, &status, &deleted, &current); e != nil {
		t.Fatal(e)
	}
	if gotLogin != login || status != "deleted" || deleted != "2026-11-15T00:00:00Z" || current != fresh {
		t.Fatal("deleted identity/current reference changed")
	}
	rows, e := dest.db.Query("SELECT id,secret_version,key_version,nonce,ciphertext,revoked_at FROM credentials WHERE user_id=? ORDER BY secret_version", uid)
	if e != nil {
		t.Fatal(e)
	}
	count := 0
	for rows.Next() {
		var cid, revoked string
		var sv, kv uint64
		var n, c []byte
		if e = rows.Scan(&cid, &sv, &kv, &n, &c, &revoked); e != nil {
			t.Fatal(e)
		}
		if revoked != "2026-11-15T00:00:00Z" {
			t.Fatal("revocation history lost")
		}
		plain, e := dest.vault.Decrypt(vault.Binding{UserID: uid, SecretVersion: sv, KeyVersion: kv}, n, c)
		if e != nil {
			t.Fatal(e)
		}
		expected := []byte(oldSecret)
		expectedID := oldID
		if sv == 2 {
			expected = []byte(newSecret)
			expectedID = fresh
		} else if sv != 1 {
			t.Fatal("unexpected history version")
		}
		equal := bytes.Equal(plain, expected)
		clear(plain)
		if !equal || cid != expectedID {
			t.Fatal("credential history changed")
		}
		foreign, e := source.vault.Decrypt(vault.Binding{UserID: uid, SecretVersion: sv, KeyVersion: kv}, n, c)
		clear(foreign)
		if e == nil {
			t.Fatal("history was not reencrypted for destination key")
		}
		count++
	}
	if e = rows.Err(); e != nil {
		t.Fatal(e)
	}
	if e = rows.Close(); e != nil {
		t.Fatal(e)
	}
	if count != 2 {
		t.Fatal("history row lost")
	}
	var kind, masterStatus string
	var protected int
	if e = dest.db.QueryRow("SELECT kind,protected,status FROM users WHERE login='master_user'").Scan(&kind, &protected, &masterStatus); e != nil {
		t.Fatal(e)
	}
	if kind != "service" || protected != 1 || masterStatus != "active" {
		t.Fatal("master role changed")
	}
	after, e := os.ReadFile(captured.Path)
	if e != nil || !bytes.Equal(before, after) {
		t.Fatal("immutable source snapshot changed")
	}
}
