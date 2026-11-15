package main

import (
	"context"
	"encoding/json"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestObservationOwnerEndpoint(t *testing.T) {
	dir := t.TempDir()
	os.Chmod(dir, 0700)
	path := filepath.Join(dir, "state.db")
	v, _ := vault.New(make([]byte, 32))
	r, e := storage.Open(context.Background(), path, v, 1)
	if e != nil {
		t.Fatal(e)
	}
	defer r.Close()
	sessions, e := auth.Open(path)
	if e != nil {
		t.Fatal(e)
	}
	defer sessions.Close()
	if e = sessions.Bootstrap(context.Background(), "owner", "fixture owner password"); e != nil {
		t.Fatal(e)
	}
	mux := http.NewServeMux()
	panelRoutes(mux, r, "", dir)
	handler := sessions.Handler(mux)
	req := httptest.NewRequest("GET", "/api/v1/system/resources", nil)
	out := httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 401 {
		t.Fatal(out.Code)
	}
	login := httptest.NewRequest("POST", "/login", strings.NewReader(url.Values{"username": {"owner"}, "password": {"fixture owner password"}}.Encode()))
	login.Header.Set("Origin", auth.Origin)
	login.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, login)
	if out.Code != 303 {
		t.Fatal(out.Code)
	}
	cookie := out.Result().Cookies()[0]
	req = httptest.NewRequest("GET", "/api/v1/system/resources", nil)
	req.AddCookie(cookie)
	out = httptest.NewRecorder()
	handler.ServeHTTP(out, req)
	if out.Code != 200 || out.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(out.Code, out.Header())
	}
	var response struct {
		Data localResources `json:"data"`
	}
	if e = json.Unmarshal(out.Body.Bytes(), &response); e != nil {
		t.Fatal(e)
	}
	if response.Data.Scope != "local_ingress" {
		t.Fatal("scope missing")
	}
	for _, secret := range []string{dir, "fixture owner password", cookie.Value} {
		if strings.Contains(out.Body.String(), secret) {
			t.Fatal("secret or path exposed")
		}
	}
}
