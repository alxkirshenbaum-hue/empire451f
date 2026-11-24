package auth

import (
	"context"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/migrations"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func masterFixture(t *testing.T) *Service {
	t.Helper()
	path := filepath.Join(t.TempDir(), "registry.db")
	os.Chmod(filepath.Dir(path), 0700)
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	for _, sql := range []string{migrations.Registry, migrations.MasterAdmin, `INSERT INTO users(id,login,kind,protected,display_name,status,created_at,updated_at) VALUES('master','master_user','service',1,'Master','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP); INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) VALUES('cred','master',1,'AES-256-GCM',zeroblob(12),zeroblob(17),1,CURRENT_TIMESTAMP); INSERT INTO user_current_credentials VALUES('master','cred',CURRENT_TIMESTAMP);`} {
		if _, err = s.db.Exec(sql); err != nil {
			t.Fatal(err)
		}
	}
	return s
}
func TestMasterBindingPolicy(t *testing.T) {
	ctx := context.Background()
	s := masterFixture(t)
	if s.RequireMaster(ctx) == nil {
		t.Fatal("unbound startup accepted")
	}
	if err := s.BindMaster(ctx, "master", "cred", []byte(" x ")); err != nil {
		t.Fatal(err)
	}
	if err := s.BindMaster(ctx, "master", "cred", []byte(" x ")); err != nil {
		t.Fatal("replay", err)
	}
	if s.BindMaster(ctx, "master", "cred", []byte("other")) == nil {
		t.Fatal("conflicting secret accepted")
	}
	if err := s.RequireMaster(ctx); err != nil {
		t.Fatal(err)
	}
	if s.Bootstrap(ctx, "owner", "independent password") == nil {
		t.Fatal("hidden owner created")
	}
	h := s.Handler(http.NotFoundHandler())
	call := func(path, body string, c *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", path, strings.NewReader(body))
		r.Header.Set("Origin", Origin)
		r.Header.Set("Content-Type", "application/json")
		if c != nil {
			r.AddCookie(c)
			r.Header.Set("X-CSRF-Token", CSRF(c.Value))
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, name := range []string{"owner", "ordinary"} {
		w := call("/api/v1/auth/login", `{"username":"`+name+`","password":" x "}`, nil)
		if w.Code != 401 {
			t.Fatalf("%s login=%d", name, w.Code)
		}
	}
	w := call("/api/v1/auth/login", `{"username":"master_user","password":" x "}`, nil)
	if w.Code != 200 {
		t.Fatalf("short login=%d", w.Code)
	}
	c := w.Result().Cookies()[0]
	var before, after string
	s.db.QueryRow("SELECT password_hash FROM admin_accounts").Scan(&before)
	if w = call("/api/v1/auth/change-password", `{}`, c); w.Code != 409 {
		t.Fatalf("password change=%d", w.Code)
	}
	s.db.QueryRow("SELECT password_hash FROM admin_accounts").Scan(&after)
	if before != after {
		t.Fatal("password mutated")
	}
	tx, _ := s.db.BeginTx(ctx, nil)
	actor, err := status.SessionOwner(ctx, tx, c.Value)
	tx.Rollback()
	if err != nil || actor != "master" {
		t.Fatal(actor, err)
	}
	if _, err = s.db.Exec(`UPDATE credentials SET revoked_at=CURRENT_TIMESTAMP WHERE id='cred'`); err != nil {
		t.Fatal(err)
	}
	tx, _ = s.db.BeginTx(ctx, nil)
	_, err = status.SessionOwner(ctx, tx, c.Value)
	tx.Rollback()
	if err == nil {
		t.Fatal("drift retained session")
	}
	if w = call("/api/v1/auth/login", `{"username":"master_user","password":" x "}`, nil); w.Code != 401 {
		t.Fatalf("drift login=%d", w.Code)
	}
}
func TestMasterRefusesExistingOwner(t *testing.T) {
	s := masterFixture(t)
	ctx := context.Background()
	if err := s.Bootstrap(ctx, "owner", "old owner password"); err != nil {
		t.Fatal(err)
	}
	if s.BindMaster(ctx, "master", "cred", []byte("short")) == nil {
		t.Fatal("legacy conflict accepted")
	}
	var n int
	s.db.QueryRow("SELECT count(*) FROM admin_accounts").Scan(&n)
	if n != 1 {
		t.Fatal("conflict changed owners")
	}
}
