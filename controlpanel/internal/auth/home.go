package auth

import (
	"database/sql"
	_ "embed"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"html/template"
	"net/http"
)

//go:embed home.html
var pageSource string

//go:embed panel.js
var panelScript []byte
var pageTemplate = template.Must(template.New("home").Parse(pageSource))

type page struct {
	MasterOnly  bool
	BasePath    string
	Profiles    []profileLink
	CSRF        string
	Error       string
	ApplyNotice string
}

type profileLink struct{ ID, Login string }

func render(w http.ResponseWriter, code int, data page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	pageTemplate.Execute(w, data)
}

func (s *Service) loginError(w http.ResponseWriter, web bool, code int) {
	if !web {
		fail(w, code)
		return
	}
	message := "Username or password is incorrect."
	if code == 429 {
		message = "Please wait a moment before signing in again."
	}
	render(w, code, page{Error: message, BasePath: s.Config().BasePath})
}

func (s *Service) home(w http.ResponseWriter, r *http.Request) {
	data := page{BasePath: s.Config().BasePath}
	master, e := s.masterMode(r.Context())
	if e != nil {
		fail(w, 503)
		return
	}
	data.MasterOnly = master
	data.ApplyNotice = caddy.ApplyNotice
	if c, err := r.Cookie("session"); err == nil {
		tx, e := s.db.BeginTx(r.Context(), nil)
		if e != nil {
			fail(w, 503)
			return
		}
		_, e = status.SessionOwner(r.Context(), tx, c.Value)
		tx.Rollback()
		if e != nil {
			http.SetCookie(w, s.cookie("", -1))
			render(w, 200, data)
			return
		}
		var id string
		err = s.db.QueryRowContext(r.Context(), `UPDATE admin_sessions SET last_seen_at=CURRENT_TIMESTAMP
 WHERE token_hash=? AND revoked_at IS NULL AND julianday(expires_at)>julianday('now')
 AND julianday(last_seen_at)>julianday('now','-30 minutes')
 AND admin_id IN (SELECT id FROM admin_accounts WHERE disabled=0)
 RETURNING id`, digest(c.Value)).Scan(&id)
		switch {
		case err == nil:
			data.CSRF = CSRF(c.Value)
			if s.profileDownloads {
				rows, err := s.db.QueryContext(r.Context(), `SELECT DISTINCT u.id,u.login FROM users u
 JOIN user_profiles p ON p.user_id=u.id JOIN template_revisions v ON v.id=p.template_revision_id
 JOIN profile_templates t ON t.id=v.template_id WHERE u.status='active' AND t.enabled=1
 AND v.status='approved' AND v.client_family='sfa' AND p.target_client IN ('sfa','sfa-1.14.4')
 ORDER BY u.login COLLATE BINARY`)
				if err != nil {
					fail(w, 503)
					return
				}
				defer rows.Close()
				for rows.Next() {
					var link profileLink
					if err := rows.Scan(&link.ID, &link.Login); err != nil {
						fail(w, 503)
						return
					}
					data.Profiles = append(data.Profiles, link)
				}
				if rows.Err() != nil {
					fail(w, 503)
					return
				}
			}
		case errors.Is(err, sql.ErrNoRows):
			http.SetCookie(w, s.cookie("", -1))
		default:
			fail(w, 503)
			return
		}
	}
	render(w, 200, data)
}
