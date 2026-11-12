// Package auth manages independent owner credentials and sessions in an existing registry.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash/maphash"
	"mime"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/argon2"
)

const Origin = "https://panel.home.arpa"
const prefix = "$argon2id$v=19$m=32768,t=2,p=1$"

var encoding = base64.RawStdEncoding

type Service struct {
	db   *sql.DB
	gate chan struct{}
	next [256]time.Time // Fixed-size buckets keep throttling memory bounded.
	seed maphash.Seed
}

func Open(path string) (*Service, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0077 != 0 {
		return nil, errors.New("registry directory must be private")
	}
	file, err := os.Lstat(path)
	if err != nil || !file.Mode().IsRegular() || file.Mode().Perm()&0077 != 0 {
		return nil, errors.New("registry must be a private regular file")
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(path)}
	db, err := sql.Open("sqlite3", uri.String()+"?mode=rw&_busy_timeout=3000&_foreign_keys=on")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Service{db: db, gate: make(chan struct{}, 1), seed: maphash.MakeSeed()}, nil
}
func (s *Service) Close() error { return s.db.Close() }
func randomBytes(n int) []byte  { b := make([]byte, n); rand.Read(b); return b }
func derive(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 2, 32768, 1, 32)
}
func (s *Service) Bootstrap(ctx context.Context, name, password string) error {
	if len(name) == 0 || len(name) > 128 || strings.TrimSpace(name) != name || len(password) < 12 || len(password) > 1024 {
		return errors.New("enter a username and a password of 12 to 1024 bytes")
	}
	salt := randomBytes(16)
	hash := prefix + encoding.EncodeToString(salt) + "$" + encoding.EncodeToString(derive(password, salt))
	result, err := s.db.ExecContext(ctx, `INSERT INTO admin_accounts(id,username,password_hash,created_at)
 SELECT ?,?,?,CURRENT_TIMESTAMP WHERE NOT EXISTS(SELECT 1 FROM admin_accounts)`, hex.EncodeToString(randomBytes(16)), name, hash)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return errors.New("owner already configured")
	}
	return nil
}
func verify(password, stored string) bool {
	salt, want := make([]byte, 16), make([]byte, 32)
	valid := false
	if body, ok := strings.CutPrefix(stored, prefix); ok {
		a, b, _ := strings.Cut(body, "$")
		x, e := encoding.DecodeString(a)
		y, f := encoding.DecodeString(b)
		if e == nil && f == nil && len(x) == 16 && len(y) == 32 {
			salt, want, valid = x, y, true
		}
	}
	return subtle.ConstantTimeCompare(derive(password, salt), want) == 1 && valid
}
func digest(value string) string { h := sha256.Sum256([]byte(value)); return hex.EncodeToString(h[:]) }
func CSRF(token string) string   { return digest("csrf/v1/" + token) }
func cookie(value string, age int) *http.Cookie {
	return &http.Cookie{Name: "session", Value: value, Path: "/", MaxAge: age, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode}
}
func fail(w http.ResponseWriter, code int) { http.Error(w, http.StatusText(code), code) }
func (s *Service) Handler(operations http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("POST /api/v1/auth/logout", s.logout)
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("session")
		if err == nil {
			// Refresh only active sessions, independently of the absolute expiry.
			_, err = s.db.ExecContext(r.Context(), `UPDATE admin_sessions SET last_seen_at=CURRENT_TIMESTAMP WHERE token_hash=? AND revoked_at IS NULL AND julianday(expires_at)>julianday('now') AND julianday(last_seen_at)>julianday('now','-30 minutes') AND julianday(last_seen_at)<julianday('now','-1 second')`, digest(c.Value))
			if err != nil {
				fail(w, 503)
				return
			}
		}
		operations.ServeHTTP(w, r)
	}))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == "POST" && r.Header.Get("Origin") != Origin {
			fail(w, 403)
			return
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	typ, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if typ != "application/json" {
		fail(w, 415)
		return
	}
	var input struct{ Username, Password string }
	b := http.MaxBytesReader(w, r.Body, 8192)
	defer b.Close()
	dec := json.NewDecoder(b)
	if dec.Decode(&input) != nil || len(input.Username) > 128 || len(input.Password) > 1024 {
		fail(w, 400)
		return
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	default:
		fail(w, 429)
		return
	}
	var id, stored string
	bucket := byte(maphash.String(s.seed, input.Username))
	if time.Now().Before(s.next[bucket]) {
		fail(w, 429)
		return
	}
	err := s.db.QueryRowContext(r.Context(), "SELECT id,password_hash FROM admin_accounts WHERE username=? AND disabled=0", input.Username).Scan(&id, &stored)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		fail(w, 503)
		return
	}
	if !verify(input.Password, stored) {
		s.next[bucket] = time.Now().Add(time.Second)
		fail(w, 401)
		return
	}
	token := base64.RawURLEncoding.EncodeToString(randomBytes(32))
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		fail(w, 503)
		return
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(r.Context(), "UPDATE admin_accounts SET last_login_at=CURRENT_TIMESTAMP WHERE id=? AND password_hash=? AND disabled=0", id, stored)
	if err != nil {
		fail(w, 503)
		return
	}
	n, err := res.RowsAffected()
	if err != nil || n != 1 {
		fail(w, 401)
		return
	}
	_, err = tx.ExecContext(r.Context(), `INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at,last_seen_at) VALUES(?,?,?,datetime('now','+12 hours'),CURRENT_TIMESTAMP)`, hex.EncodeToString(randomBytes(16)), id, digest(token))
	if err != nil || tx.Commit() != nil {
		fail(w, 503)
		return
	}
	http.SetCookie(w, cookie(token, 43200))
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"csrf_token":%q}`, CSRF(token))
}
func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("session")
	if err != nil {
		fail(w, 401)
		return
	}
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(CSRF(c.Value))) != 1 {
		fail(w, 403)
		return
	}
	res, err := s.db.ExecContext(r.Context(), `UPDATE admin_sessions SET revoked_at=CURRENT_TIMESTAMP WHERE token_hash=? AND revoked_at IS NULL AND julianday(expires_at)>julianday('now') AND julianday(last_seen_at)>julianday('now','-30 minutes') AND admin_id IN(SELECT id FROM admin_accounts WHERE disabled=0)`, digest(c.Value))
	if err != nil {
		fail(w, 503)
		return
	}
	n, err := res.RowsAffected()
	if err != nil {
		fail(w, 503)
		return
	}
	if n != 1 {
		fail(w, 401)
		return
	}
	http.SetCookie(w, cookie("", -1))
	w.WriteHeader(204)
}
