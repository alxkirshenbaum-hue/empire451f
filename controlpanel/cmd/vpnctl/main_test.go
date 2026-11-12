package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestStatusThroughPrivateAPI(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "state.db")
	key, err := vault.New(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	reg, err := storage.Open(context.Background(), path, key, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reg.Close()
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	execSQL := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	execSQL("INSERT INTO profile_templates VALUES('t','sfa','SFA','naive_https',1); INSERT INTO template_revisions(id,template_id,semver,client_family,min_version,body_json,sha256,status,created_at) VALUES('r','t','1','sfa','1','{}','test','approved','now')")
	for _, admin := range []string{"owner", "other"} {
		execSQL("INSERT INTO admin_accounts(id,username,password_hash,created_at) VALUES(?,?,?,?)", admin, admin, "hidden-test-hash", "now")
		h := sha256.Sum256([]byte(admin + "-private-token"))
		execSQL("INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at) VALUES(?,?,?,?)", admin, admin, hex.EncodeToString(h[:]), "2099-01-01T00:00:00Z")
	}
	receipt, err := reg.QueueCreate(context.Background(), "owner", "a9b5c248-884a-40f0-823a-4dae9a541e3b", storage.CreateRequest{Login: "fixture", DisplayName: "fixture", TemplateRevisionID: "r", TargetClient: "sfa"})
	if err != nil {
		t.Fatal(err)
	}
	reg.Close()
	sock := filepath.Join(dir, "api.sock")
	session := filepath.Join(dir, "session")
	t.Setenv("VPNCTL_SOCKET", sock)
	t.Setenv("VPNCTL_SESSION_FILE", session)
	changeActor := func(actor string) {
		t.Helper()
		if err := os.WriteFile(session, []byte(actor+"-private-token"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	changeActor("owner")
	start := func() func() {
		t.Helper()
		reader, err := status.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		l, err := net.Listen("unix", sock)
		if err != nil {
			reader.Close()
			t.Fatal(err)
		}
		srv := http.Server{Handler: reader.Handler()}
		go srv.Serve(l)
		return func() { srv.Close(); reader.Close() }
	}
	show := func(id string, exit int) status.Response {
		t.Helper()
		var out, errs bytes.Buffer
		got := execute([]string{"operation", "show", id, "--json"}, &out, &errs)
		if got != exit {
			t.Fatalf("exit %d wanted %d (%s)", got, exit, errs.String())
		}
		for _, secret := range []string{"private-token", "hidden-test-hash", "evidence-must-stay-private", "hidden-config-hash", "a9b5c248-884a-40f0-823a-4dae9a541e3b", "ciphertext"} {
			if strings.Contains(out.String()+errs.String(), secret) {
				t.Fatal("unexpected field or secret exposed")
			}
		}
		var reply status.Response
		if err := json.Unmarshal(out.Bytes(), &reply); err != nil {
			t.Fatal(err)
		}
		if reply.Meta.RequestID == "" {
			t.Fatal("missing request id")
		}
		return reply
	}
	stop := start()
	first := show(receipt.OperationID, 0)
	stop()
	if first.Data == nil || first.Data.Status != "queued" || first.Data.Steps == nil || len(first.Data.Steps) != 0 {
		t.Fatal("incorrect queued response")
	}
	// Simulate the future executor writing progress while the status API is disconnected.
	execSQL("UPDATE operations SET status='failed',error_code='APPLY_FAILED',finished_at='2026-11-12T12:00:00Z' WHERE id=?", receipt.OperationID)
	for _, i := range []int{2, 1} {
		execSQL("INSERT INTO operation_steps(operation_id,step_no,step_name,state,started_at,before_hash,evidence_ref) VALUES(?,?,'verify','failed','2026-11-12T11:59:00Z','hidden-config-hash','evidence-must-stay-private')", receipt.OperationID, i)
	}
	stop = start()
	defer stop()
	second := show(receipt.OperationID, 0)
	if second.Data == nil || second.Data.ID != first.Data.ID || second.Data.Status != "failed" || second.Data.Error == nil || *second.Data.Error != "APPLY_FAILED" || second.Data.Finished == nil || len(second.Data.Steps) != 2 || second.Data.Steps[0].Number != 1 {
		t.Fatal("reconnect did not recover persisted progress")
	}
	changeActor("other")
	hidden := show(receipt.OperationID, 2)
	absent := show("11111111-1111-4111-8111-111111111111", 2)
	if hidden.Data != nil || hidden.Error == nil || absent.Error == nil || *hidden.Error != *absent.Error || hidden.Error.Code != "NOT_FOUND" {
		t.Fatal("existence leak")
	}
	changeActor("owner")
	for _, q := range []string{"UPDATE admin_sessions SET revoked_at='now' WHERE id='owner'", "UPDATE admin_sessions SET revoked_at=NULL,expires_at='2001-01-01' WHERE id='owner'", "UPDATE admin_sessions SET expires_at='2099-01-01' WHERE id='owner'; UPDATE admin_accounts SET disabled=1 WHERE id='owner'"} {
		execSQL(q)
		got := show(receipt.OperationID, 3)
		if got.Data != nil || got.Error == nil || got.Error.Code != "UNAUTHENTICATED" {
			t.Fatal("inactive session accepted")
		}
	}
	var n int
	if err := db.QueryRow("SELECT count(*) FROM operations").Scan(&n); err != nil || n != 1 {
		t.Fatal("unexpected operation created")
	}
}
