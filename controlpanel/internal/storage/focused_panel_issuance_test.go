package storage

import (
	"os"
	"strings"
	"testing"
)

func TestPanelIssuanceDigestMatchesDeliveredProfile(t *testing.T) {
	_, r := fixture(t)
	template, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.db.Exec("UPDATE template_revisions SET body_json=?,sha256=?", string(template), digest(template)); err != nil {
		t.Fatal(err)
	}
	if _, err = r.InstallRoutingVariants(ctx, request.TemplateRevisionID, digest(template)); err != nil {
		t.Fatal(err)
	}
	op, err := r.QueueCreate(ctx, "owner", replayKey, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.UpdateEffectiveStateCAS(ctx, op.UserID, 1, "active"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.db.Exec("INSERT INTO admin_accounts(id,username,password_hash,created_at) VALUES('owner','owner','fixture',CURRENT_TIMESTAMP)"); err != nil {
		t.Fatal(err)
	}
	if _, err = r.db.Exec("INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at,last_seen_at) VALUES('fixture','owner',?,datetime('now','+1 hour'),CURRENT_TIMESTAMP)", digest([]byte("fixture-token"))); err != nil {
		t.Fatal(err)
	}
	blob, err := r.IssueProfile(ctx, "fixture-token", op.UserID, "vpn.example.org", ProfileOptions{Client: Client1144, PanelDomain: "vpn.example.org", PanelEntryIP: "203.0.113.4"})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(blob)
	var recorded string
	if err = r.db.QueryRow("SELECT profile_sha256 FROM profile_issuance").Scan(&recorded); err != nil {
		t.Fatal(err)
	}
	if recorded != digest(blob) {
		t.Fatal("issuance digest differs from delivered bytes")
	}
	if !strings.Contains(string(blob), `203.0.113.4/32`) || strings.Contains(string(blob), `panel.home.arpa`) {
		t.Fatal("panel destination rendering missing")
	}
}
