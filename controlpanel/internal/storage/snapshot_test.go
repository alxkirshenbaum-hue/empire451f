package storage

import (
 "bytes"
 "encoding/json"
 "errors"
 "testing"

 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestSnapshotInspectionReadOnlyAndRedacted(t *testing.T) {
 _, r, _ := mutationFixture(t)
 var before, after int
 if err := r.db.QueryRow("PRAGMA data_version").Scan(&before); err != nil { t.Fatal(err) }
 if _, err := r.db.Exec("PRAGMA query_only=ON"); err != nil { t.Fatal(err) }
 result, err := r.InspectSnapshot(ctx, "")
 if err != nil { t.Fatal(err) }
 if result.SchemaVersion != 7 || result.Users != 1 || result.Credentials != 1 || result.PendingOperations != 0 { t.Fatalf("unexpected aggregate: %+v", result) }
 encoded, err := json.Marshal(result)
 if err != nil { t.Fatal(err) }
 var fields map[string]json.RawMessage
 if err = json.Unmarshal(encoded, &fields); err != nil { t.Fatal(err) }
 if len(fields) != 4 { t.Fatalf("unexpected fields: %s", encoded) }
 for _, name := range []string{"schema_version", "users", "credentials", "pending_operations"} { if _, ok := fields[name]; !ok { t.Fatalf("missing %s", name) } }
 if err = r.db.QueryRow("PRAGMA data_version").Scan(&after); err != nil || before != after { t.Fatal("inspection changed database", err) }
}

func TestSnapshotInspectionRejectsCorruption(t *testing.T) {
 for name, statement := range map[string]string{
  "migration": "UPDATE schema_migrations SET sha256='corrupt' WHERE version=7",
  "ciphertext": "UPDATE credentials SET ciphertext=zeroblob(length(ciphertext))",
  "missing_current": "DELETE FROM user_current_credentials",
  "protected_regular": "UPDATE users SET protected=1",
 } {
  t.Run(name, func(t *testing.T) {
   _, r, _ := mutationFixture(t)
   if _, err := r.db.Exec(statement); err != nil { t.Fatal(err) }
   if _, err := r.InspectSnapshot(ctx, ""); !errors.Is(err, ErrSnapshotState) { t.Fatalf("expected state refusal, got %v", err) }
  })
 }
}

func TestSnapshotInspectionWrongVault(t *testing.T) {
 _, r, _ := mutationFixture(t)
 wrong, err := vault.New(bytes.Repeat([]byte{8}, 32))
 if err != nil { t.Fatal(err) }
 r.vault = wrong
 if _, err = r.InspectSnapshot(ctx, ""); !errors.Is(err, ErrVaultKey) { t.Fatalf("expected vault refusal, got %v", err) }
}

func TestSnapshotInspectionUnfinishedAndOwnBackup(t *testing.T) {
 for _, status := range []string{"queued", "running", "verifying", "rollback_running", "reconcile_required"} {
  t.Run(status, func(t *testing.T) {
   _, r, rec := mutationFixture(t)
   if _, err := r.db.Exec("UPDATE operations SET status=? WHERE id=?", status, rec.OperationID); err != nil { t.Fatal(err) }
   if _, err := r.InspectSnapshot(ctx, ""); !errors.Is(err, ErrSnapshotState) { t.Fatalf("unfinished accepted: %v", err) }
   if _, err := r.InspectSnapshot(ctx, rec.OperationID); !errors.Is(err, ErrSnapshotState) { t.Fatalf("wrong-kind own exclusion: %v", err) }
   if _, err := r.db.Exec("UPDATE operations SET kind='backup.create',status='running' WHERE id=?", rec.OperationID); err != nil { t.Fatal(err) }
   if _, err := r.InspectSnapshot(ctx, rec.OperationID); err != nil { t.Fatalf("own running backup refused: %v", err) }
   if _, err := r.InspectSnapshot(ctx, "missing"); !errors.Is(err, ErrSnapshotState) { t.Fatalf("missing own ID accepted: %v", err) }
  })
 }
}

func TestSnapshotInspectionPreparedRotate(t *testing.T) {
 _, r, created := mutationFixture(t)
 _, err := r.QueueOwnedMutation(ctx, "mutation-run", "owner", id(), MutationRequest{UserID: created.UserID, Action: "rotate", ExpectedVersion: 2, Reason: "synthetic"})
 if err != nil { t.Fatal(err) }
 if _, err = r.InspectSnapshot(ctx, ""); !errors.Is(err, ErrSnapshotState) { t.Fatalf("prepared rotation accepted: %v", err) }
}