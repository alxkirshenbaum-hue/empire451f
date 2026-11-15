package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOwnerIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, mutation string
		code           int
	}{{"active", "", 200}, {"missing", "", 401}, {"revoked", "UPDATE admin_sessions SET revoked_at=CURRENT_TIMESTAMP", 401}, {"idle", "UPDATE admin_sessions SET last_seen_at=datetime('now','-31 minutes')", 401}, {"expired", "UPDATE admin_sessions SET expires_at=datetime('now','-1 minute')", 401}, {"disabled", "UPDATE admin_accounts SET disabled=1", 401}} {
		t.Run(tc.name, func(t *testing.T) {
			s, h := passwordFixture(t)
			if _, e := s.db.Exec("UPDATE admin_accounts SET username='ExactOwnerCase'"); e != nil {
				t.Fatal(e)
			}
			if tc.mutation != "" {
				if _, e := s.db.Exec(tc.mutation); e != nil {
					t.Fatal(e)
				}
			}
			req := httptest.NewRequest("GET", "/api/v1/auth/me", nil)
			if tc.name != "missing" {
				req.AddCookie(&http.Cookie{Name: "session", Value: "session-one"})
			}
			out := httptest.NewRecorder()
			h.ServeHTTP(out, req)
			if out.Code != tc.code || out.Header().Get("Cache-Control") != "no-store" {
				t.Fatal(out.Code, out.Body.String())
			}
			if strings.Contains(out.Body.String(), "session-one") || strings.Contains(out.Body.String(), "password") {
				t.Fatal("credential disclosure")
			}
			if tc.code == 200 {
				var result struct {
					Data map[string]string `json:"data"`
				}
				if e := json.Unmarshal(out.Body.Bytes(), &result); e != nil {
					t.Fatal(e)
				}
				if len(result.Data) != 3 || result.Data["username"] != "ExactOwnerCase" || result.Data["role"] != "owner" || result.Data["expires_at"] == "" {
					t.Fatal(result)
				}
			} else if strings.Contains(out.Body.String(), "ExactOwnerCase") {
				t.Fatal("identity disclosure")
			}
		})
	}
}
