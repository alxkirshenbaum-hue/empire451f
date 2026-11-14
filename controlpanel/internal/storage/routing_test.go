package storage

import (
	"bytes"
	"encoding/json"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/migrations"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestRoutingOptionsAndImmutableVariants(t *testing.T) {
	_, r, created := mutationFixture(t)
	body, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	// Fixture approval is explicit; existing bindings and credentials stay intact.
	if _, err = r.db.Exec("UPDATE template_revisions SET body_json=?,sha256=?", string(body), digest(body)); err != nil {
		t.Fatal(err)
	}
	variants, err := r.InstallRoutingVariants(ctx, request.TemplateRevisionID, digest(body))
	if err != nil {
		t.Fatal(err)
	}
	replay, err := r.InstallRoutingVariants(ctx, request.TemplateRevisionID, digest(body))
	if err != nil || replay["base"] != variants["base"] || replay["ru_download_manager"] != variants["ru_download_manager"] {
		t.Fatal("variant replay", err)
	}
	old, err := r.OpenForPurpose(ctx, created.UserID, RenderProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(old)
	var baseline []byte
	for _, client := range []string{Client1144, ClientAlpha13} {
		blob, err := r.RenderProfile(ctx, created.UserID, "vpn.example.org", ProfileOptions{Client: client})
		if err != nil {
			t.Fatal(client, err)
		}
		defer clear(blob)
		if bytes.Contains(blob, []byte("package_name")) || bytes.Contains(blob, []byte("geosite-ru")) || bytes.Contains(blob, []byte(".xn--p1ai")) {
			t.Fatal("base contains RU/DM")
		}
		if !bytes.Contains(blob, []byte("panel.home.arpa")) {
			t.Fatal("lost panel route")
		}
		if baseline == nil {
			baseline = bytes.Clone(blob)
			defer clear(baseline)
		} else if !bytes.Equal(baseline, blob) {
			t.Fatal("base render diverged between clients")
		}
	}
	for _, options := range []ProfileOptions{
		{Client: Client1144, RUDM: true, Acknowledge: true},
		{Client: ClientAlpha13, RUDM: true},
		{Client: "sfa-1.15-alpha3", RUDM: true, Acknowledge: true},
		{Client: "sfa-1.15"},
	} {
		if blob, err := r.RenderProfile(ctx, created.UserID, "vpn.example.org", options); err != ErrTemplateIncompatible || blob != nil {
			t.Fatal("unsupported options accepted", err)
		}
	}
	blob, err := r.RenderProfile(ctx, created.UserID, "vpn.example.org", ProfileOptions{Client: ClientAlpha13, RUDM: true, Acknowledge: true})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(blob)
	if !bytes.Contains(blob, []byte("package_name")) || !bytes.Contains(blob, []byte("geosite-ru")) {
		t.Fatal("optional policy missing")
	}
	var got map[string]any
	if json.Unmarshal(blob, &got) != nil {
		t.Fatal("invalid optional JSON")
	}
	after, err := r.OpenForPurpose(ctx, created.UserID, RenderProfile)
	if err != nil || !bytes.Equal(after, old) {
		t.Fatal("option rotated credential", err)
	}
	clear(after)
	var saved string
	if err = r.db.QueryRow("SELECT body_json FROM template_revisions WHERE id=?", request.TemplateRevisionID).Scan(&saved); err != nil || saved != string(body) {
		t.Fatal("edited source revision", err)
	}
}

func TestProfileCheckerMatrix(t *testing.T) {
	_, r, created := mutationFixture(t)
	source, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.db.Exec("UPDATE template_revisions SET body_json=?,sha256=?", string(source), digest(source)); err != nil {
		t.Fatal(err)
	}
	if _, err = r.InstallRoutingVariants(ctx, request.TemplateRevisionID, digest(source)); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, env, version string
		options            ProfileOptions
	}{
		{"base1144", "VPN_TEST_SFA_CHECK_1144", "1.14.4", ProfileOptions{Client: Client1144}},
		{"baseAlpha13", "VPN_TEST_SFA_CHECK_ALPHA13", "1.15.0-alpha.13", ProfileOptions{Client: ClientAlpha13}},
		{"optionalAlpha13", "VPN_TEST_SFA_CHECK_ALPHA13", "1.15.0-alpha.13", ProfileOptions{Client: ClientAlpha13, RUDM: true, Acknowledge: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binary := os.Getenv(tc.env)
			if binary == "" {
				t.Skip("exact-version checker not configured")
			}
			version, err := exec.Command(binary, "version").Output()
			if err != nil || strings.Split(strings.TrimSpace(string(version)), "\n")[0] != "sing-box version "+tc.version {
				t.Fatal("wrong checker version", err)
			}
			blob, err := r.RenderProfile(ctx, created.UserID, "vpn.example.org", tc.options)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(blob)
			command := exec.Command(binary, "check", "-c", "/dev/stdin")
			command.Stdin = bytes.NewReader(blob)
			command.Dir = t.TempDir()
			if err = command.Run(); err != nil {
				t.Fatal("exact-version profile check failed", err)
			}
		})
	}
}

func TestVariantPolicyUpgradePreservesOldRevisions(t *testing.T) {
	path, r, created := mutationFixture(t)
	source, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.db.Exec("UPDATE template_revisions SET body_json=?,sha256=?", string(source), digest(source)); err != nil {
		t.Fatal(err)
	}
	oldBase, err := DeriveBaseRouting(source)
	if err != nil {
		t.Fatal(err)
	}
	oldSecret, err := r.OpenForPurpose(ctx, created.UserID, RenderProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(oldSecret)
	// Recreate schema6's immutable mapping from its distributed migration text.
	prefix := strings.Split(migrations.ProfileRouting, "ALTER TABLE")[0]
	if _, err = r.db.Exec("BEGIN IMMEDIATE; DROP TABLE profile_routing_variants;" + prefix + "DELETE FROM schema_migrations WHERE version=7; COMMIT;"); err != nil {
		t.Fatal(err)
	}
	var template string
	if err = r.db.QueryRow("SELECT template_id FROM template_revisions WHERE id=?", request.TemplateRevisionID).Scan(&template); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		id, variant string
		body        []byte
	}{{"v1-base", "base", oldBase}, {"v1-optional", "ru_download_manager", source}} {
		if _, err = r.db.Exec("INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at) VALUES(?,?,?,'sfa','1.14.4',?,?,'approved',CURRENT_TIMESTAMP)", tc.id, template, tc.id, string(tc.body), digest(tc.body)); err != nil {
			t.Fatal(err)
		}
		if _, err = r.db.Exec("INSERT INTO profile_routing_variants VALUES(?,?,?)", request.TemplateRevisionID, tc.variant, tc.id); err != nil {
			t.Fatal(err)
		}
	}
	r.Close()
	r = openTest(t, path)
	if _, err = r.InstallRoutingVariants(ctx, request.TemplateRevisionID, digest(source)); err != nil {
		t.Fatal(err)
	}
	var before, after int
	if err = r.db.QueryRow("SELECT count(*) FROM profile_routing_variants WHERE policy_version=1").Scan(&before); err != nil {
		t.Fatal(err)
	}
	if err = r.db.QueryRow("SELECT count(*) FROM profile_routing_variants WHERE policy_version=2").Scan(&after); err != nil || before != 2 || after != 2 {
		t.Fatal("policy history changed", err)
	}
	var preserved string
	if err = r.db.QueryRow("SELECT body_json FROM template_revisions WHERE id='v1-base'").Scan(&preserved); err != nil || preserved != string(oldBase) {
		t.Fatal("edited old revision", err)
	}
	secret, err := r.OpenForPurpose(ctx, created.UserID, RenderProfile)
	if err != nil || !bytes.Equal(secret, oldSecret) {
		t.Fatal("policy migration rotated credential", err)
	}
	clear(secret)
	rendered, err := r.RenderProfile(ctx, created.UserID, "vpn.example.org", ProfileOptions{Client: Client1144})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(rendered)
	if !bytes.Contains(rendered, []byte("192.0.2.119")) || !bytes.Contains(rendered, []byte("panel-dns")) {
		t.Fatal("panel destination missing")
	}
}
