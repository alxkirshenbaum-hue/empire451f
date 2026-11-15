package auth

import (
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"hash/maphash"
	"io"
	"mime"
	"net/http"
	"time"
)

// changePassword changes only the independent admin credential. VPN credentials
// and the registry vault identity are untouched. All owner sessions expire.
func (s *Service) changePassword(w http.ResponseWriter, r *http.Request) {
	c, e := r.Cookie("session")
	if e != nil || c.Value == "" || len(c.Value) > 512 {
		fail(w, 401)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(CSRF(c.Value))) != 1 {
		fail(w, 403)
		return
	}
	typ, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if typ != "application/json" {
		fail(w, 415)
		return
	}
	var input struct {
		Old     string `json:"old_password"`
		New     string `json:"new_password"`
		Confirm string `json:"confirm_password"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(&input) != nil {
		fail(w, 400)
		return
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) || len(input.Old) > 1024 || len(input.New) < 12 || len(input.New) > 1024 || input.New != input.Confirm || input.New == input.Old {
		fail(w, 400)
		return
	}
	var id, name, stored string
	e = s.db.QueryRowContext(r.Context(), `SELECT a.id,a.username,a.password_hash FROM admin_accounts a JOIN admin_sessions s ON s.admin_id=a.id WHERE s.token_hash=? AND s.revoked_at IS NULL AND a.disabled=0 AND julianday(s.expires_at)>julianday('now') AND julianday(s.last_seen_at)>julianday('now','-30 minutes')`, digest(c.Value)).Scan(&id, &name, &stored)
	if errors.Is(e, sql.ErrNoRows) {
		fail(w, 401)
		return
	}
	if e != nil {
		fail(w, 503)
		return
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	default:
		fail(w, 429)
		return
	}
	bucket := byte(maphash.String(s.seed, name))
	if time.Now().Before(s.next[bucket]) {
		fail(w, 429)
		return
	}
	if !verify(input.Old, stored) {
		s.next[bucket] = time.Now().Add(time.Second)
		fail(w, 401)
		return
	}
	salt := randomBytes(16)
	fresh := prefix + encoding.EncodeToString(salt) + "$" + encoding.EncodeToString(derive(input.New, salt))
	tx, e := s.db.BeginTx(r.Context(), nil)
	if e != nil {
		fail(w, 503)
		return
	}
	defer tx.Rollback()
	actor, e := status.SessionOwner(r.Context(), tx, c.Value)
	if errors.Is(e, status.ErrSession) || e == nil && actor != id {
		fail(w, 401)
		return
	}
	if e != nil {
		fail(w, 503)
		return
	}
	result, e := tx.ExecContext(r.Context(), "UPDATE admin_accounts SET password_hash=? WHERE id=? AND password_hash=? AND disabled=0", fresh, id, stored)
	if e != nil {
		fail(w, 503)
		return
	}
	n, e := result.RowsAffected()
	if e != nil {
		fail(w, 503)
		return
	}
	if n != 1 {
		fail(w, 401)
		return
	}
	if _, e = tx.ExecContext(r.Context(), "UPDATE admin_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE admin_id=? AND revoked_at IS NULL", id); e != nil {
		fail(w, 503)
		return
	}
	if _, e = tx.ExecContext(r.Context(), `INSERT INTO audit_runs(id,script_version,started_at,finished_at,summary) VALUES(?,'owner-password-v1',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'Independent owner password changed; owner sessions revoked')`, hex.EncodeToString(randomBytes(16))); e != nil {
		fail(w, 503)
		return
	}
	if e = tx.Commit(); e != nil {
		fail(w, 503)
		return
	}
	http.SetCookie(w, cookie("", -1))
	w.WriteHeader(http.StatusNoContent)
}
