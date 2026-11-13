package storage

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestRenderBoundSFA(t *testing.T) {
	_, r := fixture(t)
	template, err := os.ReadFile("../../../templates/sfa-profile.json")
	if err != nil {
		t.Fatal(err)
	}
	dbExec := func(query string, args ...any) {
		t.Helper()
		if _, err := r.db.Exec(query, args...); err != nil {
			t.Fatal(err)
		}
	}
	dbExec("UPDATE template_revisions SET body_json=?,sha256=?", string(template), fmt.Sprintf("%x", sha256.Sum256(template)))
	op, err := r.QueueCreate(ctx, "owner", replayKey, request)
	if err != nil {
		t.Fatal(err)
	}
	denied := func(domain string) {
		t.Helper()
		if blob, err := r.RenderSFA1144(ctx, op.UserID, domain); err == nil || blob != nil {
			t.Fatal("unexpected render")
		}
	}
	const domain = "vpn.example.org"
	denied(domain)
	if _, err = r.UpdateEffectiveStateCAS(ctx, op.UserID, 1, "active"); err != nil {
		t.Fatal(err)
	}
	denied("https://invalid.example")
	blob, err := r.RenderSFA1144(ctx, op.UserID, domain)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(blob)
	password, err := r.OpenForPurpose(ctx, op.UserID, RenderProfile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(password)
	var want, got map[string]any
	if json.Unmarshal(template, &want) != nil || json.Unmarshal(blob, &got) != nil {
		t.Fatal("invalid JSON")
	}
	proxy := want["outbounds"].([]any)[0].(map[string]any)
	proxy["username"], proxy["password"], proxy["server"] = request.Login, string(password), domain
	if !reflect.DeepEqual(want, got) {
		t.Fatal("unexpected rendered profile")
	}
	if checker := os.Getenv("VPN_TEST_SFA_CHECK"); checker != "" {
		cmd := exec.Command(checker, "check", "-c", "/dev/stdin")
		cmd.Dir = filepath.Clean(t.TempDir())
		cmd.Stdin = bytes.NewReader(blob)
		if err := cmd.Run(); err != nil {
			t.Fatal("sing-box check:", err)
		}
	}
	dbExec("UPDATE template_revisions SET status='retired'")
	denied(domain)
	dbExec("UPDATE template_revisions SET status='approved',min_version='1.15.0'")
	denied(domain)
	dbExec("UPDATE template_revisions SET min_version='1.14.4',sha256='changed'")
	denied(domain)
	dbExec("UPDATE template_revisions SET sha256=?", fmt.Sprintf("%x", sha256.Sum256(template)))
	if _, err = r.UpdateEffectiveStateCAS(ctx, op.UserID, 2, "disabled"); err != nil {
		t.Fatal(err)
	}
	denied(domain)
}
