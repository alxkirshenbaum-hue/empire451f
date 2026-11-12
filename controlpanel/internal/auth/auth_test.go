package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/migrations"
)

func TestOwnerSession(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry.db")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err = s.db.Exec(migrations.Registry); err != nil {
		t.Fatal(err)
	}
	if err = s.Bootstrap(context.Background(), "owner", "synthetic password"); err != nil {
		t.Fatal(err)
	}
	if s.Bootstrap(context.Background(), "other", "other test password") == nil {
		t.Fatal("second owner accepted")
	}
	reader, err := status.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	h := s.Handler(reader.Handler())
	t.Run("browser form", func(t *testing.T) {
		callForm := func(path string, values url.Values, c *http.Cookie, origin string, want int) *httptest.ResponseRecorder {
			t.Helper()
			method := "POST"
			if values == nil {
				method = "GET"
			}
			req := httptest.NewRequest(method, path, strings.NewReader(values.Encode()))
			req.Header.Set("Origin", origin)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if c != nil {
				req.AddCookie(c)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, req)
			if w.Code != want {
				t.Fatalf("%s got %d, want %d", path, w.Code, want)
			}
			return w
		}
		initial := callForm("/", nil, nil, "", 200)
		if !strings.Contains(initial.Body.String(), `action="/login" method="post"`) {
			t.Fatal("missing login form")
		}
		fields := url.Values{"username": {"owner"}, "password": {"synthetic password"}}
		callForm("/login", fields, nil, "https://outside.invalid", 403)
		login := callForm("/login", fields, nil, Origin, 303)
		c := login.Result().Cookies()[0]
		home := callForm("/", nil, c, "", 200)
		if !strings.Contains(home.Body.String(), CSRF(c.Value)) || strings.Contains(home.Body.String(), c.Value) {
			t.Fatal("invalid signed-in page")
		}
		callForm("/logout", url.Values{}, c, Origin, 403)
		callForm("/logout", url.Values{"csrf": {CSRF(c.Value)}}, c, Origin, 303)
		old := callForm("/", nil, c, "", 200)
		if !strings.Contains(old.Body.String(), "Owner sign in") {
			t.Fatal("revoked browser session")
		}
	})
	call := func(method, path, origin, password string, c *http.Cookie, csrf string, want int) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(map[string]string{"username": "owner", "password": password})
		req := httptest.NewRequest(method, path, strings.NewReader(string(b)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", origin)
		if c != nil {
			req.AddCookie(c)
		}
		req.Header.Set("X-CSRF-Token", csrf)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s: got %d, want %d", path, w.Code, want)
		}
		return w
	}
	const login = "/api/v1/auth/login"
	const logout = "/api/v1/auth/logout"
	const op = "/api/v1/operations/00000000-0000-4000-8000-000000000001"
	call("POST", login, "https://external.invalid", "synthetic password", nil, "", 403)
	call("POST", login, Origin, "wrong", nil, "", 401)
	call("POST", login, Origin, "wrong", nil, "", 429)
	clear(s.next[:])
	issue := func() (*http.Cookie, string) {
		start := time.Now()
		w := call("POST", login, Origin, "synthetic password", nil, "", 200)
		t.Logf("Argon2id login %v", time.Since(start))
		c := w.Result().Cookies()[0]
		if !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
			t.Fatal("cookie attributes")
		}
		var response struct {
			Token string `json:"csrf_token"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil || response.Token == "" {
			t.Fatal("missing csrf token")
		}
		return c, response.Token
	}
	first, csrf := issue()
	second, _ := issue()
	call("GET", op, "", "", first, "", 404)
	call("POST", logout, Origin, "", first, "", 403)
	call("POST", logout, "https://external.invalid", "", first, csrf, 403)
	call("POST", logout, Origin, "", first, csrf, 204)
	call("GET", op, "", "", first, "", 401)
	call("GET", op, "", "", second, "", 404)
	for _, field := range []string{"last_seen_at", "expires_at"} {
		c, _ := issue()
		if _, err = s.db.Exec("UPDATE admin_sessions SET "+field+"=datetime('now','-1 hour') WHERE token_hash=?", digest(c.Value)); err != nil {
			t.Fatal(err)
		}
		call("GET", op, "", "", c, "", 401)
	}
	s.Close()
	w := call("GET", op, "", "", second, "", 503)
	var problem status.Response
	if err = json.Unmarshal(w.Body.Bytes(), &problem); err != nil || problem.Error == nil || problem.Error.Code != "DEPENDENCY_UNAVAILABLE" || !problem.Error.Retryable || problem.Meta.RequestID == "" {
		t.Fatal("missing OPS-02 dependency error")
	}
}
