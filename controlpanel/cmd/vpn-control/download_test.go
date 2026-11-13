package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestOwnerDownloadsActiveProfile(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	cipher, err := vault.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := storage.Open(ctx, path, cipher, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	tpl, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	exec("INSERT INTO profile_templates VALUES('t','sfa','SFA','naive_https',1)")
	exec("INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at) VALUES('r','t','1','sfa','1.14.4',?,?,'approved',CURRENT_TIMESTAMP)", string(tpl), fmt.Sprintf("%x", sha256.Sum256(tpl)))
	sessions, err := auth.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer sessions.Close()
	sessions.EnableProfileDownloads()
	if err = sessions.Bootstrap(ctx, "owner", "synthetic password"); err != nil {
		t.Fatal(err)
	}
	receipt, err := reg.QueueCreate(ctx, "owner", "00000000-0000-4000-8000-000000000001", storage.CreateRequest{Login: "Test-User", DisplayName: "Test User", TemplateRevisionID: "r", TargetClient: "sfa"})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/users/{id}/profiles/download", download(reg, "entry.example"))
	handler := sessions.Handler(mux)
	form := url.Values{"username": {"owner"}, "password": {"synthetic password"}}
	login := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	login.Header.Set("Origin", auth.Origin)
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, login)
	if resp.Code != 303 {
		t.Fatal("login failed")
	}
	cookie := resp.Result().Cookies()[0]
	fetch := func(method string, c *http.Cookie, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(method, "/api/v1/users/"+receipt.UserID+"/profiles/download?client=sfa-1.14.4", nil)
		if c != nil {
			req.AddCookie(c)
		}
		resp := httptest.NewRecorder()
		handler.ServeHTTP(resp, req)
		if resp.Code != want || resp.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("download status %d, want %d", resp.Code, want)
		}
		return resp
	}
	fetch("GET", nil, 401)
	fetch("GET", cookie, 404)
	if _, err = reg.UpdateEffectiveStateCAS(ctx, receipt.UserID, 1, "active"); err != nil {
		t.Fatal(err)
	}
	fetch("HEAD", cookie, 405)
	home := httptest.NewRequest("GET", "/", nil)
	home.AddCookie(cookie)
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, home)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "/api/v1/users/"+receipt.UserID+"/profiles/download?client=sfa-1.14.4") {
		t.Fatal("profile download link missing")
	}
	exec("CREATE TRIGGER reject_audit BEFORE INSERT ON profile_issuance BEGIN SELECT RAISE(ABORT,'fixture'); END")
	fetch("GET", cookie, 503)
	var issued sql.NullString
	if err = db.QueryRow("SELECT last_issued_at FROM user_profiles").Scan(&issued); err != nil || issued.Valid {
		t.Fatal("issuance did not roll back")
	}
	exec("DROP TRIGGER reject_audit")
	result := fetch("GET", cookie, 200)
	var profile struct {
		Outbounds []struct{ Username, Password, Server string }
	}
	if !strings.HasPrefix(result.Header().Get("Content-Disposition"), "attachment;") || json.Unmarshal(result.Body.Bytes(), &profile) != nil || len(profile.Outbounds) == 0 {
		t.Fatal("missing profile attachment")
	}
	secret, err := reg.OpenForPurpose(ctx, receipt.UserID, storage.RenderProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(secret)
	proxy := profile.Outbounds[0]
	if proxy.Username != "Test-User" || proxy.Password != string(secret) || proxy.Server != "entry.example" {
		t.Fatal("incorrect connection details")
	}
	exec("UPDATE admin_sessions SET revoked_at=CURRENT_TIMESTAMP")
	fetch("GET", cookie, 401)
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM profile_issuance e JOIN admin_accounts a ON a.id=e.admin_id JOIN user_profiles p ON p.id=e.profile_id WHERE e.event='PROFILE_ISSUED' AND a.username='owner' AND e.issued_at=p.last_issued_at`).Scan(&count); err != nil || count != 1 {
		t.Fatal("wrong issuance record", err)
	}
}
