package storage

import "testing"

// Both SQLite CURRENT_TIMESTAMP and RFC3339 are written by existing producers.
// Lexical ordering puts an earlier RFC3339 record ahead of later SQLite UTC.
func TestInventoryChronologicalUTC(t *testing.T) {
	_, r := fixture(t)
	for _, row := range []struct{ id, stamp string }{
		{"earlier", "2026-11-16T01:00:00Z"},
		{"latest", "2026-11-16 09:00:00"},
		{"offset", "2026-11-16T10:00:00+03:00"},
	} {
		if _, err := r.db.ExecContext(ctx, `INSERT INTO audit_runs(id,script_version,started_at,summary) VALUES(?,'fixture',?,'metadata only')`, row.id, row.stamp); err != nil {
			t.Fatal(err)
		}
		if _, err := r.db.ExecContext(ctx, `INSERT INTO backups(id,created_at,format_version,encrypted_path,sha256,size_bytes,source_generation,status) VALUES(?,?,1,'/synthetic/never-read','synthetic',1,1,'created')`, row.id, row.stamp); err != nil {
			t.Fatal(err)
		}
	}
	audits, err := r.AuditInventory(ctx)
	if err != nil || len(audits) != 3 || audits[0].ID != "latest" || audits[1].ID != "offset" || audits[2].ID != "earlier" || audits[0].Finished != nil || audits[0].Checks != 0 {
		t.Fatalf("audit chronology or missing evidence: %+v %v", audits, err)
	}
	backups, err := r.BackupInventory(ctx)
	if err != nil || len(backups) != 3 || backups[0].ID != "latest" || backups[1].ID != "offset" || backups[2].ID != "earlier" || backups[0].Verified != nil || backups[0].Status != "created" {
		t.Fatalf("backup chronology or missing evidence: %+v %v", backups, err)
	}
}
