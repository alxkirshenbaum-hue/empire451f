package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/auth"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/caddy"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
)

func panelJSON(w http.ResponseWriter, code int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"data": data, "meta": status.NewMetadata()})
}
func panelError(w http.ResponseWriter, err error) {
	code, name := 503, "DEPENDENCY_UNAVAILABLE"
	switch {
	case errors.Is(err, status.ErrSession):
		code, name = 401, "UNAUTHENTICATED"
	case errors.Is(err, storage.ErrProtectedAccount):
		code, name = 403, "PROTECTED_ACCOUNT"
	case errors.Is(err, storage.ErrPreconditionRequired):
		code, name = 428, "PRECONDITION_REQUIRED"
	case errors.Is(err, storage.ErrVersionConflict):
		code, name = 412, "VERSION_CONFLICT"
	case errors.Is(err, storage.ErrOperationInProgress), errors.Is(err, storage.ErrJournalConflict):
		code, name = 409, "OPERATION_IN_PROGRESS"
	case errors.Is(err, storage.ErrIdempotencyConflict):
		code, name = 409, "IDEMPOTENCY_KEY_REUSED"
	case errors.Is(err, storage.ErrAlreadyExists):
		code, name = 409, "ALREADY_EXISTS"
	case errors.Is(err, storage.ErrCapacity):
		code, name = 409, "USER_CAPACITY_REACHED"
	case errors.Is(err, storage.ErrLegacyConflict):
		code, name = 409, "LEGACY_MIGRATION_REQUIRED"
	case errors.Is(err, storage.ErrInvalidTransition):
		code, name = 409, "INVALID_TRANSITION"
	case errors.Is(err, storage.ErrTemplateIncompatible):
		code, name = 422, "TEMPLATE_INCOMPATIBLE"
	case errors.Is(err, storage.ErrInvalidMetadata):
		code, name = 400, "VALIDATION_ERROR"
	case errors.Is(err, sql.ErrNoRows):
		code, name = 404, "NOT_FOUND"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": name, "message": name, "retryable": code >= 500 || name == "OPERATION_IN_PROGRESS"}, "meta": status.NewMetadata()})
}
func panelBody(w http.ResponseWriter, r *http.Request, value any) bool {
	kind, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" {
		http.Error(w, "Expected application/json", 415)
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(value) != nil {
		panelError(w, storage.ErrInvalidMetadata)
		return false
	}
	var extra any
	if !errors.Is(d.Decode(&extra), io.EOF) {
		panelError(w, storage.ErrInvalidMetadata)
		return false
	}
	return true
}
func panelRoutes(mux *http.ServeMux, registry *storage.Registry, run string) {
	owner := func(mutate bool, handler func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie("session")
			if err != nil {
				panelError(w, status.ErrSession)
				return
			}
			actor, err := registry.Owner(r.Context(), cookie.Value)
			if err != nil {
				panelError(w, err)
				return
			}
			if mutate {
				if r.Header.Get("Origin") != auth.Origin || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(auth.CSRF(cookie.Value))) != 1 {
					http.Error(w, "Forbidden", 403)
					return
				}
				if run == "" {
					panelError(w, storage.ErrLegacyConflict)
					return
				}
				if !status.ValidID(r.Header.Get("Idempotency-Key")) {
					panelError(w, storage.ErrInvalidMetadata)
					return
				}
			}
			handler(w, r, actor)
		}
	}
	receipt := func(w http.ResponseWriter, rec storage.Receipt, err error) {
		if err != nil {
			panelError(w, err)
			return
		}
		panelJSON(w, 202, map[string]string{"operation_id": rec.OperationID, "user_id": rec.UserID})
	}
	mux.HandleFunc("GET /api/v1/dashboard", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		data, err := registry.Counts(r.Context())
		if err != nil {
			panelError(w, err)
			return
		}
		panelJSON(w, 200, map[string]any{"counts": data, "live_observed_state": "unknown", "exit_local_audit_state": "unknown"})
	}))
	mux.HandleFunc("GET /api/v1/templates", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		data, err := registry.ApprovedTemplates(r.Context())
		if err != nil {
			panelError(w, err)
			return
		}
		panelJSON(w, 200, data)
	}))
	mux.HandleFunc("GET /api/v1/capabilities", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		ready, err := registry.MutationReady(r.Context(), run)
		if err != nil {
			panelError(w, err)
			return
		}
		backupReady, err := registry.BackupConfigured(r.Context())
		if err != nil { panelError(w,err); return }
		panelJSON(w, 200, map[string]any{"clients": []string{storage.Client1144, storage.ClientAlpha13}, "routing_warning": storage.RoutingWarning, "apply_notice": caddy.ApplyNotice, "mutations_enabled": ready, "capacity": 100, "live_observed_state": "unknown", "backup_creation_available": backupReady})
	}))
	mux.HandleFunc("GET /api/v1/users", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		q := r.URL.Query()
		limit, offset := 100, 0
		var err error
		if q.Has("limit") {
			limit, err = strconv.Atoi(q.Get("limit"))
			if err != nil {
				panelError(w, storage.ErrInvalidMetadata)
				return
			}
		}
		if q.Has("cursor") {
			offset, err = strconv.Atoi(q.Get("cursor"))
			if err != nil {
				panelError(w, storage.ErrInvalidMetadata)
				return
			}
		}
		users, err := registry.UserPage(r.Context(), q.Get("search"), q.Get("status"), limit, offset)
		if err != nil {
			panelError(w, err)
			return
		}
		next := ""
		if len(users) == limit {
			next = strconv.Itoa(offset + limit)
		}
		panelJSON(w, 200, map[string]any{"users": users, "next_cursor": next})
	}))
	mux.HandleFunc("POST /api/v1/users", owner(true, func(w http.ResponseWriter, r *http.Request, actor string) {
		var input struct {
			Login       string `json:"login"`
			DisplayName string `json:"display_name"`
			Template    string `json:"template_revision_id"`
			Client      string `json:"target_client"`
		}
		if !panelBody(w, r, &input) {
			return
		}
		rec, err := registry.QueueOwnedUser(r.Context(), run, actor, r.Header.Get("Idempotency-Key"), storage.CreateRequest{Login: input.Login, DisplayName: input.DisplayName, TemplateRevisionID: input.Template, TargetClient: input.Client})
		receipt(w, rec, err)
	}))
	mux.HandleFunc("GET /api/v1/users/{id}", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		if !status.ValidID(r.PathValue("id")) {
			panelError(w, sql.ErrNoRows)
			return
		}
		user, err := registry.GetUser(r.Context(), r.PathValue("id"))
		if err != nil {
			panelError(w, err)
			return
		}
		credential, err := registry.CredentialStatus(r.Context(), user.ID)
		if err != nil {
			panelError(w, err)
			return
		}
		panelJSON(w, 200, map[string]any{"user": user, "credential": credential, "observed_state": "unknown", "new_sessions_revoked": user.Status == "disabled" || user.Status == "deleted", "existing_sessions_terminated": "unknown"})
	}))
	mux.HandleFunc("GET /api/v1/users/{id}/credential", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		data, err := registry.CredentialStatus(r.Context(), r.PathValue("id"))
		if err != nil {
			panelError(w, err)
			return
		}
		panelJSON(w, 200, data)
	}))
	mux.HandleFunc("PATCH /api/v1/users/{id}", owner(true, func(w http.ResponseWriter, r *http.Request, actor string) {
		var input struct {
			Name    string `json:"display_name"`
			Version int64  `json:"expected_version"`
		}
		if !panelBody(w, r, &input) {
			return
		}
		rec, err := registry.QueueOwnedRename(r.Context(), run, actor, r.Header.Get("Idempotency-Key"), r.PathValue("id"), input.Version, input.Name)
		receipt(w, rec, err)
	}))
	change := func(action string) http.HandlerFunc {
		return owner(true, func(w http.ResponseWriter, r *http.Request, actor string) {
			var input struct {
				Version int64  `json:"expected_version"`
				Reason  string `json:"reason"`
				Confirm bool   `json:"confirm_delete"`
			}
			if !panelBody(w, r, &input) {
				return
			}
			rec, err := registry.QueueOwnedMutation(r.Context(), run, actor, r.Header.Get("Idempotency-Key"), storage.MutationRequest{UserID: r.PathValue("id"), Action: action, ExpectedVersion: input.Version, Reason: input.Reason, ConfirmDelete: input.Confirm})
			receipt(w, rec, err)
		})
	}
	mux.HandleFunc("POST /api/v1/users/{id}/disable", change("disable"))
	mux.HandleFunc("POST /api/v1/users/{id}/enable", change("enable"))
	mux.HandleFunc("DELETE /api/v1/users/{id}", change("delete"))
	mux.HandleFunc("POST /api/v1/users/{id}/credential/rotate", change("rotate"))
	mux.HandleFunc("POST /api/v1/users/{id}/credential/revoke", change("revoke"))
	for _, path := range []string{"GET /api/v1/operations", "GET /api/v1/users/{id}/history"} {
		mux.HandleFunc(path, owner(false, func(w http.ResponseWriter, r *http.Request, actor string) {
			data, err := registry.OwnerOperations(r.Context(), actor, r.PathValue("id"), 100)
			if err != nil {
				panelError(w, err)
				return
			}
			panelJSON(w, 200, data)
		}))
	}
	mux.HandleFunc("POST /api/v1/users/{id}/validate", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		user, err := registry.GetUser(r.Context(), r.PathValue("id"))
		if err != nil {
			panelError(w, err)
			return
		}
		panelJSON(w, 200, map[string]any{"user": user, "observed_state": "unknown", "verification": "not_available", "mutated": false})
	}))
	mux.HandleFunc("GET /api/v1/audits", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		data, err := registry.AuditInventory(r.Context())
		if err != nil {
			panelError(w, err)
			return
		}
		panelJSON(w, 200, data)
	}))
	mux.HandleFunc("GET /api/v1/backups", owner(false, func(w http.ResponseWriter, r *http.Request, _ string) {
		data, err := registry.BackupInventory(r.Context())
		if err != nil {
			panelError(w, err)
			return
		}
		panelJSON(w, 200, data)
	}))
	maintenanceRoutes(mux,registry,run,owner)
}
