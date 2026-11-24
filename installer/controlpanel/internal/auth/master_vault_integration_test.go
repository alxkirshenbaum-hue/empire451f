package auth_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestMasterVaultIdentityAndProfile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	key := bytes.Repeat([]byte{0x35}, 32)
	defer clear(key)
	cipher, err := vault.New(key)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := storage.Open(ctx, path, cipher, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	body, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	approved := fmt.Sprintf("%x", sha256.Sum256(body))
	revision, err := registry.InstallInitialSFA(ctx, body, approved)
	if err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_busy_timeout=3000")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, e := db.ExecContext(ctx, query, args...); e != nil {
			t.Fatal(e)
		}
	}
	const uid = "11111111-1111-4111-8111-111111111111"
	const cid = "22222222-2222-4222-8222-222222222222"
	secret := []byte(" x ")
	defer clear(secret)
	nonce, ciphertext, err := cipher.Encrypt(vault.Binding{UserID: uid, SecretVersion: 1, KeyVersion: 1}, secret)
	if err != nil {
		t.Fatal(err)
	}
	exec(`INSERT INTO users(id,login,kind,protected,source,display_name,status,created_at,updated_at) VALUES(?,'master_user','service',1,'legacy_import','Master','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`, uid)
	exec(`INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) VALUES(?,?,1,'AES-256-GCM',?,?,1,CURRENT_TIMESTAMP)`, cid, uid, nonce, ciphertext)
	exec(`INSERT INTO user_current_credentials VALUES(?,?,CURRENT_TIMESTAMP)`, uid, cid)
	if err = registry.BindMissingLegacyProfiles(ctx, revision, approved); err != nil {
		t.Fatal(err)
	}
	id, current, plain, err := registry.MasterOwnerCredential(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if id != uid || current != cid || !bytes.Equal(plain, secret) {
		t.Fatal("vault lookup changed canonical identity or secret")
	}
	sessions, err := auth.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	if err = sessions.BindMaster(ctx, id, current, plain); err != nil {
		t.Fatal(err)
	}
	if err = sessions.BindMaster(ctx, id, current, plain); err != nil {
		t.Fatal("binding replay", err)
	}
	if err = sessions.RequireMaster(ctx); err != nil {
		t.Fatal(err)
	}
	if sessions.Bootstrap(ctx, "owner", "independent owner password") == nil {
		t.Fatal("independent owner accepted")
	}
	h := sessions.Handler(http.NotFoundHandler())
	request := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Origin", auth.Origin)
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
			r.Header.Set("X-CSRF-Token", auth.CSRF(cookie.Value))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	login := request("POST", "/api/v1/auth/login", `{"username":"master_user","password":" x "}`, nil)
	if login.Code != 200 {
		t.Fatalf("vault master login=%d", login.Code)
	}
	cookie := login.Result().Cookies()[0]
	me := request("GET", "/api/v1/auth/me", "", cookie)
	if me.Code != 200 {
		t.Fatalf("identity=%d", me.Code)
	}
	var identity struct{ Data struct{ ID, Username string } }
	if json.Unmarshal(me.Body.Bytes(), &identity) != nil || identity.Data.ID != uid || identity.Data.Username != "master_user" {
		t.Fatal("noncanonical identity")
	}
	options := storage.ProfileOptions{Client: storage.Client1144}
	profile, err := registry.IssueProfile(ctx, cookie.Value, uid, "vpn.example.org", options)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(profile)
	var document struct {
		Outbounds []struct{ Type, Username, Password string }
	}
	if err = json.Unmarshal(profile, &document); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, out := range document.Outbounds {
		if out.Type == "naive" {
			found = true
			if out.Username != "master_user" || out.Password != string(secret) {
				t.Fatal("profile credential changed")
			}
		}
	}
	if !found {
		t.Fatal("missing naive outbound")
	}
	var historyHash, actor string
	if err = db.QueryRowContext(ctx, `SELECT profile_sha256,admin_id FROM profile_issuance ORDER BY rowid DESC LIMIT 1`).Scan(&historyHash, &actor); err != nil {
		t.Fatal(err)
	}
	if historyHash != fmt.Sprintf("%x", sha256.Sum256(profile)) || actor != uid {
		t.Fatal("issuance evidence mismatch")
	}
	snapshot := func() (string, string, string) {
		t.Helper()
		var hash, credential string
		var sealed []byte
		if e := db.QueryRowContext(ctx, `SELECT a.password_hash,cc.credential_id,c.ciphertext FROM admin_accounts a JOIN user_current_credentials cc ON cc.user_id=a.id JOIN credentials c ON c.id=cc.credential_id WHERE a.id=?`, uid).Scan(&hash, &credential, &sealed); e != nil {
			t.Fatal(e)
		}
		return hash, credential, string(sealed)
	}
	hashBefore, credBefore, sealedBefore := snapshot()
	if w := request("POST", "/api/v1/auth/change-password", `{"old_password":" x ","new_password":"new independent password","confirm_password":"new independent password"}`, cookie); w.Code != 409 {
		t.Fatalf("independent password change=%d", w.Code)
	}
	hashAfter, credAfter, sealedAfter := snapshot()
	if hashAfter != hashBefore || credAfter != credBefore || sealedAfter != sealedBefore {
		t.Fatal("password rejection mutated credentials")
	}
	nonce2, sealed2, err := cipher.Encrypt(vault.Binding{UserID: uid, SecretVersion: 2, KeyVersion: 1}, []byte("next"))
	if err != nil {
		t.Fatal(err)
	}
	const cid2 = "33333333-3333-4333-8333-333333333333"
	exec(`INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) VALUES(?,?,2,'AES-256-GCM',?,?,1,CURRENT_TIMESTAMP)`, cid2, uid, nonce2, sealed2)
	exec(`UPDATE user_current_credentials SET credential_id=? WHERE user_id=?`, cid2, uid)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, sessionErr := status.SessionOwner(ctx, tx, cookie.Value)
	tx.Rollback()
	if sessionErr == nil {
		t.Fatal("stale binding retained session")
	}
	if sessions.RequireMaster(ctx) == nil {
		t.Fatal("stale startup accepted")
	}
	if w := request("GET", "/api/v1/auth/me", "", cookie); w.Code != 401 {
		t.Fatalf("stale identity=%d", w.Code)
	}
	if _, err = registry.IssueProfile(ctx, cookie.Value, uid, "vpn.example.org", options); err == nil {
		t.Fatal("stale session issued profile")
	}
	if w := request("POST", "/api/v1/auth/login", `{"username":"master_user","password":" x "}`, nil); w.Code != 401 {
		t.Fatalf("stale login=%d", w.Code)
	}
}
