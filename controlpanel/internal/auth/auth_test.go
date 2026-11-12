package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
}
