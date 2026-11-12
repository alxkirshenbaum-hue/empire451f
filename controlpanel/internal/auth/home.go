package auth

import (
	"database/sql"
	_ "embed"
	"errors"
	"html/template"
	"net/http"
)

//go:embed home.html
var pageSource string
var pageTemplate = template.Must(template.New("home").Parse(pageSource))

type page struct {
	CSRF  string
	Error string
}

func render(w http.ResponseWriter, code int, data page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	pageTemplate.Execute(w, data)
}

func loginError(w http.ResponseWriter, web bool, code int) {
	if !web {
		fail(w, code)
		return
	}
	message := "Username or password is incorrect."
	if code == 429 {
		message = "Please wait a moment before signing in again."
	}
	render(w, code, page{Error: message})
}

func (s *Service) home(w http.ResponseWriter, r *http.Request) {
	var data page
	if c, err := r.Cookie("session"); err == nil {
		var id string
		err = s.db.QueryRowContext(r.Context(), `UPDATE admin_sessions SET last_seen_at=CURRENT_TIMESTAMP
 WHERE token_hash=? AND revoked_at IS NULL AND julianday(expires_at)>julianday('now')
 AND julianday(last_seen_at)>julianday('now','-30 minutes')
 AND admin_id IN (SELECT id FROM admin_accounts WHERE disabled=0)
 RETURNING id`, digest(c.Value)).Scan(&id)
		switch {
		case err == nil:
			data.CSRF = CSRF(c.Value)
		case errors.Is(err, sql.ErrNoRows):
			http.SetCookie(w, cookie("", -1))
		default:
			fail(w, 503)
			return
		}
	}
	render(w, 200, data)
}
