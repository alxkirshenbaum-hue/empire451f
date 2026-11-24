package auth

import (
	"context"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/migrations"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPanelConfig(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://example.com/", "https://EXAMPLE.com", "https://user@example.com", "https://example.com:443", "https://example.com?", "https://example.com/#x", "https://example.com\\evil", "null"} {
		if _, err := ParseConfig(origin, "/"); err == nil {
			t.Errorf("accepted %q", origin)
		}
	}
	for _, base := range []string{"//", "/abc/", "/0123456789abcdef0123456789abcdef", "/0123456789ABCDEF0123456789ABCDEF/", "/../"} {
		if _, err := ParseConfig("https://example.com", base); err == nil {
			t.Errorf("accepted base %q", base)
		}
	}
	c, err := ParseConfig("", "")
	if err != nil || c.Origin != Origin || c.BasePath != "/" {
		t.Fatal(c, err)
	}
}
func TestPanelExternalPrefix(t *testing.T) {
	const base = "/0123456789abcdef0123456789abcdef/"
	const origin = "https://example.com"
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
	c, err := ParseConfig(origin, base)
	if err != nil {
		t.Fatal(err)
	}
	s.Configure(c)
	h := s.Handler(http.NotFoundHandler())
	get := httptest.NewRecorder()
	h.ServeHTTP(get, httptest.NewRequest("GET", "/", nil))
	if !strings.Contains(get.Body.String(), `action="`+base+`login"`) {
		t.Fatal(get.Body.String())
	}
	fields := url.Values{"username": {"owner"}, "password": {"synthetic password"}}
	call := func(o string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "/login", strings.NewReader(fields.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", o)
		r.Host = "spoof.invalid"
		r.Header.Set("X-Forwarded-Host", "spoof.invalid")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	for _, o := range []string{Origin, "https://spoof.invalid", "null", ""} {
		if w := call(o); w.Code != 403 {
			t.Fatal(o, w.Code)
		}
	}
	w := call(origin)
	if w.Code != 303 || w.Header().Get("Location") != base {
		t.Fatal(w.Code, w.Header())
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Path != base || !cookie.Secure || !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatal(cookie)
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(cookie)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if !strings.Contains(w.Body.String(), `data-base-path="`+base+`"`) || !strings.Contains(w.Body.String(), `src="`+base+`assets/panel.js"`) {
		t.Fatal(w.Body.String())
	}
	r = httptest.NewRequest("POST", "/logout", strings.NewReader(url.Values{"csrf": {CSRF(cookie.Value)}}.Encode()))
	r.AddCookie(cookie)
	r.Header.Set("Origin", origin)
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 303 || w.Result().Cookies()[0].Path != base || w.Result().Cookies()[0].MaxAge != -1 {
		t.Fatal(w.Code, w.Header())
	}
}
