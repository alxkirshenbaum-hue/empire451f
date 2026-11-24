package storage

import (
	"bytes"
	"database/sql"
	"errors"
	"testing"
)

func TestUserMetadataContract(t *testing.T) {
	path, r := fixture(t)
	first, err := r.QueueCreate(ctx, "owner", replayKey, request)
	if err != nil {
		t.Fatal(err)
	}
	u, err := r.GetUser(ctx, first.UserID)
	if err != nil || u.Login != request.Login || u.Version != 1 {
		t.Fatal("get metadata", err)
	}
	alt := request
	alt.Login = "test-user"
	if _, err = r.QueueCreate(ctx, "owner", id(), alt); err != nil {
		t.Fatal(err)
	}
	page, err := r.ListUsers(ctx, 1, 1)
	if err != nil || len(page) != 1 || page[0].Login != "test-user" {
		t.Fatal("exact-case page", err)
	}
	if _, err = r.ListUsers(ctx, 101, 0); !errors.Is(err, ErrInvalidMetadata) {
		t.Fatal("page limit")
	}
	if _, err = r.UpdateDisplayName(ctx, u.ID, 0, "new"); !errors.Is(err, ErrPreconditionRequired) {
		t.Fatal("missing version")
	}
	other := openTest(t, path)
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, reg := range []*Registry{r, other} {
		go func(client *Registry) {
			<-start
			_, e := client.UpdateDisplayName(ctx, u.ID, u.Version, "new")
			results <- e
		}(reg)
	}
	close(start)
	a, b := <-results, <-results
	if !(a == nil && errors.Is(b, ErrVersionConflict) || b == nil && errors.Is(a, ErrVersionConflict)) {
		t.Fatal("concurrent update", a, b)
	}
	saved, err := r.GetUser(ctx, u.ID)
	if err != nil || saved.Version != 2 || saved.DisplayName != "new" || saved.Login != u.Login {
		t.Fatal("wrong updated metadata")
	}
	_, err = r.db.Exec("INSERT INTO users(id,login,kind,protected,source,display_name,status,created_at,updated_at) VALUES('master','master_user','service',1,'legacy_import','master','active','now','now')")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.UpdateDisplayName(ctx, "master", 1, "changed"); !errors.Is(err, ErrProtectedAccount) {
		t.Fatal("protected account")
	}
}

// TestEffectiveStateAndSecretPurpose exercises the worker-facing contracts together.
func TestEffectiveStateAndSecretPurpose(t *testing.T) {
	_, r := fixture(t)
	rec, err := r.QueueCreate(ctx, "owner", replayKey, request)
	if err != nil {
		t.Fatal(err)
	}
	version := int64(1)
	change := func(next string) {
		t.Helper()
		u, e := r.UpdateEffectiveStateCAS(ctx, rec.UserID, version, next)
		if e != nil || u.Status != next || u.Version != version+1 {
			t.Fatal("state transition", next, e)
		}
		version = u.Version
	}
	refuse := func(p SecretPurpose, want error) {
		t.Helper()
		value, e := r.OpenForPurpose(ctx, rec.UserID, p)
		if len(value) != 0 || !errors.Is(e, want) {
			t.Fatal("credential purpose accepted", p, e)
		}
	}
	current, e := r.OpenForPurpose(ctx, rec.UserID, PrepareAuth)
	if e != nil {
		t.Fatal(e)
	}
	defer clear(current)
	refuse(RenderProfile, sql.ErrNoRows)
	refuse(ReenableAuth, sql.ErrNoRows)
	refuse("unspecified", ErrSecretPurpose)
	if _, e = r.UpdateEffectiveStateCAS(ctx, rec.UserID, 0, "active"); !errors.Is(e, ErrPreconditionRequired) {
		t.Fatal("accepted missing version")
	}
	change("active")
	profile, e := r.OpenForPurpose(ctx, rec.UserID, RenderProfile)
	if e != nil || !bytes.Equal(profile, current) {
		t.Fatal("profile credential mismatch")
	}
	clear(profile)
	if _, e = r.UpdateEffectiveStateCAS(ctx, rec.UserID, 1, "disabled"); !errors.Is(e, ErrVersionConflict) {
		t.Fatal("accepted stale version")
	}
	if _, e = r.UpdateEffectiveStateCAS(ctx, rec.UserID, version, "deleted"); !errors.Is(e, ErrInvalidTransition) {
		t.Fatal("accepted direct deletion")
	}
	change("disabled")
	refuse(RenderProfile, sql.ErrNoRows)
	refuse(PrepareAuth, sql.ErrNoRows)
	enable, e := r.OpenForPurpose(ctx, rec.UserID, ReenableAuth)
	if e != nil || !bytes.Equal(enable, current) {
		t.Fatal("enable credential mismatch")
	}
	clear(enable)
	change("active")
	change("disabled")
	change("deleting")
	change("deleted")
	var deleted string
	if e = r.db.QueryRow("SELECT deleted_at FROM users WHERE id=?", rec.UserID).Scan(&deleted); e != nil || deleted == "" {
		t.Fatal("missing deletion timestamp")
	}
	for _, p := range []SecretPurpose{PrepareAuth, RenderProfile, ReenableAuth} {
		refuse(p, sql.ErrNoRows)
	}
	if _, e = r.UpdateEffectiveStateCAS(ctx, rec.UserID, version, "active"); !errors.Is(e, sql.ErrNoRows) {
		t.Fatal("revived tombstone")
	}
	_, e = r.db.Exec("INSERT INTO users(id,login,display_name,kind,protected,status,created_at,updated_at) VALUES('master','master_user','master','service',1,'active','now','now')")
	if e != nil {
		t.Fatal(e)
	}
	if _, e = r.UpdateEffectiveStateCAS(ctx, "master", 1, "disabled"); !errors.Is(e, ErrProtectedAccount) {
		t.Fatal("changed service identity")
	}
	other := request
	other.Login = "uncertain"
	rec, e = r.QueueCreate(ctx, "owner", id(), other)
	if e != nil {
		t.Fatal(e)
	}
	version = 1
	change("reconcile_required")
	for _, p := range []SecretPurpose{PrepareAuth, RenderProfile, ReenableAuth} {
		refuse(p, sql.ErrNoRows)
	}
	if _, e = r.UpdateEffectiveStateCAS(ctx, rec.UserID, version, "active"); !errors.Is(e, ErrInvalidTransition) {
		t.Fatal("unverified reconciliation")
	}
}
