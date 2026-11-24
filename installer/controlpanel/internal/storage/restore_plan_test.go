//go:build linux

package storage

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestReadonlyRestorePlan(t *testing.T) {
	_, r, u := snapshotFixture(t)
	run := id()
	if _, e := r.db.Exec(`INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'verified_cutover','{}','now','verified_cutover')`, run); e != nil {
		t.Fatal(e)
	}
	backup, e := r.CaptureSnapshot(ctx, captureParent(t), "")
	if e != nil {
		t.Fatal(e)
	}
	secondRun := id()
	if _, e = r.db.Exec(`INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'verified_cutover','{}','now','verified_cutover')`, secondRun); e != nil {
		t.Fatal(e)
	}
	if _, e = r.db.Exec("UPDATE users SET status='disabled',row_version=row_version+1 WHERE id=?", u.UserID); e != nil {
		t.Fatal(e)
	}
	current, e := r.CaptureSnapshot(ctx, captureParent(t), "")
	if e != nil {
		t.Fatal(e)
	}
	beforeCurrent, _ := os.ReadFile(current.Path)
	beforeBackup, _ := os.ReadFile(backup.Path)
	binding := RestorePlanBinding{OwnerRun: run, CurrentObservedManifestGeneration: 9, ExpectedManifestGeneration: 9, BackupManifestGeneration: 3, CurrentDBSHA256: current.SHA256, BackupDBSHA256: backup.SHA256}
	report, e := PlanRestore(ctx, current.Path, backup.Path, r.vault, r.vault, binding)
	if e != nil {
		t.Fatal(e)
	}
	if report.ReactivationRiskCount != 1 || len(report.Changes) != 1 || report.Changes[0].UserID != u.UserID || report.Changes[0].CurrentStatus != "disabled" || report.Changes[0].BackupStatus != "active" || report.Changes[0].CredentialMayChange {
		t.Fatalf("wrong impact %+v", report)
	}
	raw, e := json.Marshal(report)
	if e != nil {
		t.Fatal(e)
	}
	if bytes.Contains(raw, []byte("synthetic-master-password")) || bytes.Contains(raw, []byte(current.Path)) || bytes.Contains(raw, []byte("ciphertext")) {
		t.Fatal("secret/path in plan")
	}
	same, e := PlanRestore(ctx, backup.Path, backup.Path, r.vault, r.vault, RestorePlanBinding{OwnerRun: run, CurrentObservedManifestGeneration: 3, ExpectedManifestGeneration: 3, BackupManifestGeneration: 3, CurrentDBSHA256: backup.SHA256, BackupDBSHA256: backup.SHA256})
	if e != nil || len(same.Changes) != 0 {
		t.Fatal("unchanged plan", same, e)
	}
	for _, scenario := range []string{"stale", "current-hash", "backup-hash", "unfinished", "empty-owner", "wrong-owner", "cross-owner"} {
		t.Run(scenario, func(t *testing.T) {
			b := binding
			switch scenario {
			case "cross-owner":
				b.OwnerRun = secondRun
			case "empty-owner":
				b.OwnerRun = ""
			case "wrong-owner":
				b.OwnerRun = id()
			case "stale":
				b.ExpectedManifestGeneration--
			case "current-hash":
				b.CurrentDBSHA256 = strings.Repeat("a", 64)
			case "backup-hash":
				b.BackupDBSHA256 = strings.Repeat("b", 64)
			case "unfinished":
				b.OwnBackupOperationID = id()
			}
			if _, e := PlanRestore(ctx, current.Path, backup.Path, r.vault, r.vault, b); e == nil {
				t.Fatal("invalid plan accepted")
			}
		})
	}
	afterCurrent, _ := os.ReadFile(current.Path)
	afterBackup, _ := os.ReadFile(backup.Path)
	if !bytes.Equal(beforeCurrent, afterCurrent) || !bytes.Equal(beforeBackup, afterBackup) {
		t.Fatal("readonly plan wrote source")
	}
}
