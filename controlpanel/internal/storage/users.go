package storage

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"unicode/utf8"
)

// UserMetadata excludes credentials, template bodies and profile downloads.
type UserMetadata struct {
	ID, Login, DisplayName, Kind, Status string
	Protected                            bool
	Version                              int64
}

var (
	ErrPreconditionRequired = errors.New("expected user version required")
	ErrVersionConflict      = errors.New("user version changed")
	ErrInvalidMetadata      = errors.New("invalid user metadata")
)

type UserRepository interface {
	GetUser(context.Context, string) (UserMetadata, error)
	ListUsers(context.Context, int, int) ([]UserMetadata, error)
	UpdateDisplayName(context.Context, string, int64, string) (UserMetadata, error)
	QueueCreate(context.Context, string, string, CreateRequest) (Receipt, error)
}

var _ UserRepository = (*Registry)(nil)

const userColumns = "id,login,display_name,kind,status,protected,row_version"

type userRow interface{ Scan(...any) error }

func scanUser(row userRow) (UserMetadata, error) {
	var u UserMetadata
	err := row.Scan(&u.ID, &u.Login, &u.DisplayName, &u.Kind, &u.Status, &u.Protected, &u.Version)
	return u, err
}
func (r *Registry) GetUser(ctx context.Context, id string) (UserMetadata, error) {
	return scanUser(r.db.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id=?", id))
}
func (r *Registry) ListUsers(ctx context.Context, limit, offset int) ([]UserMetadata, error) {
	if limit < 1 || limit > 100 || offset < 0 {
		return nil, ErrInvalidMetadata
	}
	rows, err := r.db.QueryContext(ctx, "SELECT "+userColumns+" FROM users WHERE status<>'deleted' ORDER BY login COLLATE BINARY LIMIT ? OFFSET ?", limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]UserMetadata, 0, limit)
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, u)
	}
	return result, rows.Err()
}
func validDisplayName(name string) bool {
	return utf8.ValidString(name) && utf8.RuneCountInString(name) >= 1 && utf8.RuneCountInString(name) <= 80 && !strings.ContainsRune(name, 0)
}
func (r *Registry) UpdateDisplayName(ctx context.Context, id string, expected int64, name string) (UserMetadata, error) {
	var zero UserMetadata
	if expected < 1 {
		return zero, ErrPreconditionRequired
	}
	if !validDisplayName(name) {
		return zero, ErrInvalidMetadata
	}
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return zero, err
	}
	defer tx.Rollback()
	u, err := scanUser(tx.QueryRowContext(ctx, "SELECT "+userColumns+" FROM users WHERE id=?", id))
	if err != nil {
		return zero, err
	}
	if u.Status == "deleted" {
		return zero, sql.ErrNoRows
	}
	if u.Protected {
		return zero, ErrProtectedAccount
	}
	if u.Version != expected {
		return zero, ErrVersionConflict
	}
	u, err = scanUser(tx.QueryRowContext(ctx, "UPDATE users SET display_name=?,updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now'),row_version=row_version+1 WHERE id=? AND row_version=? RETURNING "+userColumns, name, id, expected))
	if err != nil {
		return zero, err
	}
	if err = tx.Commit(); err != nil {
		return zero, err
	}
	return u, nil
}

var ErrProtectedAccount = errors.New("protected account")
