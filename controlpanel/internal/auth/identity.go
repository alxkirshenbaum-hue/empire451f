package auth

import (
	"database/sql"
	"encoding/json"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"net/http"
)

// identity exposes only the independent panel owner and the current session expiry.
func (s *Service) identity(w http.ResponseWriter, r *http.Request) {
	c, e := r.Cookie("session")
	if e != nil {
		fail(w, 401)
		return
	}
	tx, e := s.db.BeginTx(r.Context(), &sql.TxOptions{ReadOnly: true})
	if e != nil {
		fail(w, 503)
		return
	}
	defer tx.Rollback()
	actor, e := status.SessionOwner(r.Context(), tx, c.Value)
	if errors.Is(e, status.ErrSession) {
		fail(w, 401)
		return
	}
	if e != nil {
		fail(w, 503)
		return
	}
	var name, expiry string
	if e = tx.QueryRowContext(r.Context(), `SELECT a.username,s.expires_at FROM admin_accounts a JOIN admin_sessions s ON s.admin_id=a.id WHERE a.id=? AND s.token_hash=?`, actor, digest(c.Value)).Scan(&name, &expiry); e != nil {
		fail(w, 503)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"username": name, "role": "owner", "expires_at": expiry}})
}
