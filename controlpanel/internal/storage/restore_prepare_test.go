//go:build linux

package storage

import (
	"bytes"
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareRestoreCopy(t *testing.T) {
	for _, scenario := range []string{"success", "owner", "own", "backup", "cipher", "empty-own", "other", "abort"} {
		t.Run(scenario, func(t *testing.T) {
			_, r, u := snapshotFixture(t)
			run := id()
			if _, e := r.db.Exec(`INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'verified_cutover','{}','now','verified_cutover')`, run); e != nil {
				t.Fatal(e)
			}
			if e := r.ConfigureBackups(ctx, "fixture-key"); e != nil {
				t.Fatal(e)
			}
			j, e := r.QueueMaintenance(ctx, run, "owner", id(), MaintenanceRequest{Action: "backup.create"})
			if e != nil {
				t.Fatal(e)
			}
			if e = r.Transition(ctx, j.OperationID, "queued", "running"); e != nil {
				t.Fatal(e)
			}
			if scenario == "other" {
				_, e = r.db.Exec(`INSERT INTO operations(id,actor_id,kind,status,idempotency_key,request_hash,correlation_id,created_at) VALUES(?,'owner','user.create','queued',?,?,?,'now')`, id(), id(), strings.Repeat("a", 64), id())
				if e != nil {
					t.Fatal(e)
				}
			}
			if scenario == "abort" {
				_, e = r.db.Exec(`CREATE TRIGGER fail_restore BEFORE INSERT ON audit_runs BEGIN SELECT RAISE(ABORT,'fixture'); END`)
				if e != nil {
					t.Fatal(e)
				}
			}
			if _, e = r.db.Exec(`INSERT INTO admin_accounts(id,username,password_hash,created_at) VALUES('restore-owner','owner','synthetic-hash','now'); INSERT INTO admin_sessions(id,admin_id,token_hash,expires_at) VALUES('restore-session','restore-owner','synthetic-token','future')`); e != nil {
				t.Fatal(e)
			}
			sourceParent := t.TempDir()
			os.Chmod(sourceParent, 0700)
			// Other unfinished operations must already be refused at capture.
			source, e := r.CaptureSnapshot(ctx, sourceParent, j.OperationID)
			if scenario == "other" {
				if e == nil {
					t.Fatal("capture accepted other unfinished operation")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			before, e := os.ReadFile(source.Path)
			if e != nil {
				t.Fatal(e)
			}
			binding := RestoreBinding{OwnerRun: run, OwnOperationID: j.OperationID, BackupID: j.BackupID, CipherSHA256: strings.Repeat("a", 64)}
			switch scenario {
			case "owner":
				binding.OwnerRun = id()
			case "own":
				binding.OwnOperationID = id()
			case "backup":
				binding.BackupID = id()
			case "cipher":
				binding.CipherSHA256 = "bad"
			case "empty-own":
				binding.OwnOperationID = ""
			}
			parent := t.TempDir()
			os.Chmod(parent, 0700)
			out, e := PrepareRestoreCopy(context.Background(), source.Path, parent, r.vault, binding)
			after, _ := os.ReadFile(source.Path)
			if !bytes.Equal(before, after) {
				t.Fatal("source changed")
			}
			if scenario != "success" {
				if e == nil {
					t.Fatal("invalid restore accepted")
				}
				entries, _ := os.ReadDir(parent)
				if len(entries) != 0 {
					t.Fatal("candidate leaked")
				}
				return
			}
			if e != nil {
				t.Fatal(e)
			}
			if out.Path == source.Path || filepath.Dir(out.Path) == filepath.Dir(source.Path) {
				t.Fatal("source reused")
			}
			db, e := sql.Open("sqlite3", snapshotURI(out.Path)+"?mode=ro")
			if e != nil {
				t.Fatal(e)
			}
			defer db.Close()
			var state, code string
			if e = db.QueryRow("SELECT status,error_code FROM operations WHERE id=?", j.OperationID).Scan(&state, &code); e != nil || state != "failed" || code != "RESTORED_INTERRUPTED" {
				t.Fatal(state, code, e)
			}
			var count int
			if e = db.QueryRow("SELECT count(*) FROM admin_sessions").Scan(&count); e != nil || count != 0 {
				t.Fatal("restored sessions survived", count, e)
			}
			if e = db.QueryRow("SELECT count(*) FROM admin_accounts WHERE id='restore-owner'").Scan(&count); e != nil || count != 1 {
				t.Fatal("owner lost", count, e)
			}
			if e = db.QueryRow("SELECT count(*) FROM maintenance_intents WHERE operation_id=?", j.OperationID).Scan(&count); e != nil || count != 1 {
				t.Fatal("intent history lost", count, e)
			}
			if e = db.QueryRow("SELECT count(*) FROM audit_runs WHERE script_version='restore-copy-v1'").Scan(&count); e != nil || count != 1 {
				t.Fatal(count, e)
			}
			candidate, e := Open(ctx, out.Path, r.vault, r.keyVersion)
			if e != nil {
				t.Fatal(e)
			}
			defer candidate.Close()
			plain, e := candidate.OpenForPurpose(ctx, u.UserID, RenderProfile)
			if e != nil {
				t.Fatal(e)
			}
			clear(plain)
		})
	}
}
