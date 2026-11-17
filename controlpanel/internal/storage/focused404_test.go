package storage

import (
	"bytes"
	"errors"
	"os"
	"testing"
)

// Reproduce the legacy importer state: credentials exist but profile links do not.
func TestImportedProfile404Repair(t *testing.T) {
	_, r := fixture(t)
	body, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.db.Exec("UPDATE template_revisions SET body_json=?,sha256=?", string(body), digest(body)); err != nil {
		t.Fatal(err)
	}
	if _, err = r.InstallRoutingVariants(ctx, request.TemplateRevisionID, digest(body)); err != nil {
		t.Fatal(err)
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := r.db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO admin_accounts(id,username,password_hash,created_at) VALUES('owner','owner','fixture',CURRENT_TIMESTAMP)")
	exec("INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at,last_seen_at) VALUES('fixture','owner',?,datetime('now','+1 hour'),CURRENT_TIMESTAMP)", digest([]byte("fixture-token")))
	exec("INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES('import-fixture','planned','{}','now','planned')")
	options := []ProfileOptions{{Client: Client1144}, {Client: ClientAlpha13}, {Client: ClientAlpha13, RUDM: true, Acknowledge: true}}
	for i, login := range []string{"Imported-User", "master_user"} {
		action := legacyAction{Login: login, Kind: "regular"}
		if i == 1 {
			action.Kind = "service"
			action.Protected = true
		}
		tx, err := r.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = r.stageLegacyUser(ctx, tx, "import-fixture", i+1, action, "synthetic-imported-password"); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err = tx.Commit(); err != nil {
			t.Fatal(err)
		}
		var userID string
		if err = r.db.QueryRow("SELECT id FROM users WHERE login=?", login).Scan(&userID); err != nil {
			t.Fatal(err)
		}
		exec("UPDATE users SET status='active' WHERE id=?", userID) // Legacy cutover activates protected master internally.
		// Establish the expected approved render before removing the missing link.
		if err = r.BindMissingLegacyProfiles(ctx, request.TemplateRevisionID, digest(body)); err != nil {
			t.Fatal(err)
		}
		secret, err := r.OpenForPurpose(ctx, userID, RenderProfile)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(secret)
		var baseline [][]byte
		for _, option := range options {
			blob, err := r.RenderProfile(ctx, userID, "vpn.example.org", option)
			if err != nil {
				t.Fatal(err)
			}
			baseline = append(baseline, blob)
			defer clear(blob)
		}
		exec("DELETE FROM user_profiles WHERE user_id=?", userID)
		if _, err = r.RenderSFA1144(ctx, userID, "vpn.example.org"); err == nil {
			t.Fatal("missing binding did not reproduce 404")
		}
		if err = r.BindMissingLegacyProfiles(ctx, request.TemplateRevisionID, "wrong"); !errors.Is(err, ErrLegacyDrift) {
			t.Fatal("approval ignored", err)
		}
		for n := 0; n < 2; n++ {
			if err = r.BindMissingLegacyProfiles(ctx, request.TemplateRevisionID, digest(body)); err != nil {
				t.Fatal(err)
			}
		}
		for j, option := range options {
			blob, err := r.IssueProfile(ctx, "fixture-token", userID, "vpn.example.org", option)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(blob, baseline[j]) {
				t.Fatal("repair changed profile bytes")
			}
			var recorded string
			if err = r.db.QueryRow("SELECT profile_sha256 FROM profile_issuance WHERE profile_id=(SELECT id FROM user_profiles WHERE user_id=?) ORDER BY rowid DESC LIMIT 1", userID).Scan(&recorded); err != nil {
				t.Fatal(err)
			}
			if recorded != digest(blob) {
				t.Fatal("issuance hash mismatch")
			}
			clear(blob)
		}
		after, err := r.OpenForPurpose(ctx, userID, RenderProfile)
		if err != nil || !bytes.Equal(secret, after) {
			t.Fatal("repair changed credentials", err)
		}
		clear(after)
	}
	var count int
	if err = r.db.QueryRow("SELECT count(*) FROM user_profiles").Scan(&count); err != nil || count != 2 {
		t.Fatal("repair not idempotent", count, err)
	}
	if err = r.db.QueryRow("SELECT count(*) FROM profile_issuance").Scan(&count); err != nil || count != 6 {
		t.Fatal("issuance history lost", count, err)
	}
}
