package storage

import (
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
