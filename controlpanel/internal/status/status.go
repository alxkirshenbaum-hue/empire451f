// Package status serves the metadata-only view of a queued operation.
package status

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var uuid = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
var ErrSession = errors.New("session required")
var ErrID = errors.New("invalid operation ID")

func ValidID(id string) bool { return uuid.MatchString(id) }

type Step struct {
	Number   int     `json:"step_no"`
	Name     string  `json:"name"`
	State    string  `json:"state"`
	Error    *string `json:"error_code,omitempty"`
	Started  *string `json:"started_at,omitempty"`
	Finished *string `json:"finished_at,omitempty"`
}
type Operation struct {
	ID            string  `json:"operation_id"`
	Kind          string  `json:"kind"`
	Status        string  `json:"status"`
	ObservedState string  `json:"observed_state"`
	Target        *string `json:"target_id,omitempty"`
	Error         *string `json:"error_code,omitempty"`
	Created       string  `json:"created_at"`
	Started       *string `json:"started_at,omitempty"`
	Finished      *string `json:"finished_at,omitempty"`
	Steps         []Step  `json:"steps"`
}
type Reader struct{ db *sql.DB }

func Open(path string) (*Reader, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uri := url.URL{Scheme: "file", Path: filepath.ToSlash(abs)}
	if !strings.HasPrefix(uri.Path, "/") {
		uri.Path = "/" + uri.Path
	}
	db, err := sql.Open("sqlite3", uri.String()+"?mode=ro&_query_only=on&_busy_timeout=3000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if err = db.Ping(); err != nil {
		db.Close()
		return nil, err
	}
	return &Reader{db}, nil
}
func (r *Reader) Close() error { return r.db.Close() }

func (r *Reader) Lookup(ctx context.Context, token, id string) (Operation, error) {
	var op Operation
	if token == "" || len(token) > 512 {
		return op, ErrSession
	}
	h := sha256.Sum256([]byte(token))
	tx, err := r.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return op, err
	}
	defer tx.Rollback()
	var actor string
	err = tx.QueryRowContext(ctx, `SELECT a.id FROM admin_sessions s JOIN admin_accounts a ON a.id=s.admin_id
 WHERE s.token_hash=? AND s.revoked_at IS NULL AND a.disabled=0 AND julianday(s.expires_at)>julianday('now')`, hex.EncodeToString(h[:])).Scan(&actor)
	if errors.Is(err, sql.ErrNoRows) {
		return op, ErrSession
	}
	if err != nil {
		return op, err
	}
	if !ValidID(id) {
		return op, ErrID
	}
	// OPS-02 reads the persisted journal. It does not probe the data plane.
	op.ObservedState = "unknown"
	err = tx.QueryRowContext(ctx, `SELECT id,kind,status,target_id,error_code,created_at,started_at,finished_at
 FROM operations WHERE id=? AND actor_id=?`, strings.ToLower(id), actor).Scan(&op.ID, &op.Kind, &op.Status, &op.Target, &op.Error, &op.Created, &op.Started, &op.Finished)
	if err != nil {
		return op, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT step_no,step_name,state,error_code,started_at,finished_at
 FROM operation_steps WHERE operation_id=? ORDER BY step_no`, op.ID)
	if err != nil {
		return op, err
	}
	defer rows.Close()
	op.Steps = []Step{}
	for rows.Next() {
		var step Step
		if err := rows.Scan(&step.Number, &step.Name, &step.State, &step.Error, &step.Started, &step.Finished); err != nil {
			return op, err
		}
		op.Steps = append(op.Steps, step)
	}
	if err := rows.Err(); err != nil {
		return op, err
	}
	return op, tx.Commit()
}

type Metadata struct {
	RequestID  string `json:"request_id"`
	ObservedAt string `json:"observed_state_at"`
}
type Problem struct {
	Code      string `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
}
type Response struct {
	Data  *Operation `json:"data,omitempty"`
	Error *Problem   `json:"error,omitempty"`
	Meta  Metadata   `json:"meta"`
}

func (r *Reader) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/operations/{id}", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		var raw [16]byte
		rand.Read(raw[:])
		result := Response{Meta: Metadata{RequestID: hex.EncodeToString(raw[:]), ObservedAt: time.Now().UTC().Format(time.RFC3339Nano)}}
		code := http.StatusOK
		id := req.PathValue("id")
		cookie, err := req.Cookie("session")
		switch {
		case err != nil || cookie.Value == "":
			code = 401
			result.Error = &Problem{"UNAUTHENTICATED", "Admin session required", false}
		default:
			op, e := r.Lookup(req.Context(), cookie.Value, id)
			switch {
			case errors.Is(e, ErrSession):
				code = 401
				result.Error = &Problem{"UNAUTHENTICATED", "Admin session required", false}
			case errors.Is(e, ErrID):
				code = 400
				result.Error = &Problem{"VALIDATION_ERROR", "Invalid operation ID", false}
			case errors.Is(e, sql.ErrNoRows):
				code = 404
				result.Error = &Problem{"NOT_FOUND", "Operation not found", false}
			case e != nil:
				code = 500
				result.Error = &Problem{"INTERNAL_ERROR", "Status unavailable", false}
			default:
				result.Data = &op
			}
		}
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(result)
	})
	return mux
}
