package auth

import (
	"context"
	"encoding/json"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/migrations"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func passwordFixture(t *testing.T) (*Service, http.Handler) {
	t.Helper()
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "state.db")
	os.WriteFile(path, nil, 0600)
	s, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { s.Close() })
	if _, e = s.db.Exec(migrations.Registry); e != nil {
		t.Fatal(e)
	}
	if e = s.Bootstrap(context.Background(), "owner", "original owner password"); e != nil {
		t.Fatal(e)
	}
	for _, token := range []string{"session-one", "session-two"} {
		if _, e = s.db.Exec(`INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at,last_seen_at) SELECT ?,id,?,datetime('now','+12 hours'),CURRENT_TIMESTAMP FROM admin_accounts`, token, digest(token)); e != nil {
			t.Fatal(e)
		}
	}
	return s, s.Handler(http.NotFoundHandler())
}
func passwordRequest(h http.Handler, token, origin, csrf, old, new, confirm string) *httptest.ResponseRecorder {
	raw, _ := json.Marshal(map[string]string{"old_password": old, "new_password": new, "confirm_password": confirm})
	req := httptest.NewRequest("POST", "/api/v1/auth/change-password", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Origin", origin)
	req.Header.Set("X-CSRF-Token", csrf)
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "session", Value: token})
	}
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	return out
}
func TestOwnerPasswordAtomicChangeAndRevocation(t *testing.T) {
	s, h := passwordFixture(t)
	out := passwordRequest(h, "session-one", Origin, CSRF("session-one"), "original owner password", "replacement owner password", "replacement owner password")
	if out.Code != 204 || out.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(out.Code, out.Body.String())
	}
	cookies := out.Result().Cookies()
	if len(cookies) != 1 || cookies[0].MaxAge != -1 || !cookies[0].Secure || !cookies[0].HttpOnly {
		t.Fatal("cookie not expired safely")
	}
	var hash string
	s.db.QueryRow("SELECT password_hash FROM admin_accounts").Scan(&hash)
	if verify("original owner password", hash) || !verify("replacement owner password", hash) {
		t.Fatal("wrong credential state")
	}
	var active, audit int
	s.db.QueryRow("SELECT count(*) FROM admin_sessions WHERE revoked_at IS NULL").Scan(&active)
	s.db.QueryRow("SELECT count(*) FROM audit_runs WHERE script_version='owner-password-v1'").Scan(&audit)
	if active != 0 || audit != 1 {
		t.Fatal(active, audit)
	}
	for _, token := range []string{"session-one", "session-two"} {
		if got := passwordRequest(h, token, Origin, CSRF(token), "replacement owner password", "another password value", "another password value"); got.Code != 401 {
			t.Fatal("old session survived", got.Code)
		}
	}
	login := httptest.NewRequest("POST", "/api/v1/auth/login", strings.NewReader(`{"Username":"owner","Password":"replacement owner password"}`))
	login.Header.Set("Origin", Origin)
	login.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, login)
	if rr.Code != 200 {
		t.Fatal("new login failed", rr.Code)
	}
}
func TestOwnerPasswordFailuresLeaveState(t *testing.T) {
	for _, tc := range []struct {
		name, token, origin, csrf, old, new string
		code                                int
		fault                               bool
	}{{"unauth", "", Origin, "", "original owner password", "replacement owner password", 401, false}, {"origin", "session-one", "https://wrong.invalid", CSRF("session-one"), "original owner password", "replacement owner password", 403, false}, {"csrf", "session-one", Origin, "wrong", "original owner password", "replacement owner password", 403, false}, {"old", "session-one", Origin, CSRF("session-one"), "wrong", "replacement owner password", 401, false}, {"weak", "session-one", Origin, CSRF("session-one"), "original owner password", "short", 400, false}, {"audit fault", "session-one", Origin, CSRF("session-one"), "original owner password", "replacement owner password", 503, true}} {
		t.Run(tc.name, func(t *testing.T) {
			s, h := passwordFixture(t)
			var before string
			s.db.QueryRow("SELECT password_hash FROM admin_accounts").Scan(&before)
			if tc.fault {
				if _, e := s.db.Exec("CREATE TRIGGER reject_password_audit BEFORE INSERT ON audit_runs BEGIN SELECT RAISE(ABORT,'fixture'); END"); e != nil {
					t.Fatal(e)
				}
			}
			out := passwordRequest(h, tc.token, tc.origin, tc.csrf, tc.old, tc.new, tc.new)
			if out.Code != tc.code {
				t.Fatal(out.Code)
			}
			var after string
			var active int
			s.db.QueryRow("SELECT password_hash FROM admin_accounts").Scan(&after)
			s.db.QueryRow("SELECT count(*) FROM admin_sessions WHERE revoked_at IS NULL").Scan(&active)
			if before != after || active != 2 || len(out.Result().Cookies()) != 0 {
				t.Fatal("failed change mutated state")
			}
		})
	}
}
func TestOwnerPasswordConcurrentChanges(t *testing.T) {
	_, h := passwordFixture(t)
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes <- passwordRequest(h, "session-one", Origin, CSRF("session-one"), "original owner password", "replacement owner password", "replacement owner password").Code
		}()
	}
	wg.Wait()
	close(codes)
	success := 0
	for code := range codes {
		if code == 204 {
			success++
		} else if code != 429 && code != 401 {
			t.Fatal(code)
		}
	}
	if success != 1 {
		t.Fatal(success)
	}
}
