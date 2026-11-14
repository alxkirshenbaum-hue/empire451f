package storage

import (
 "bytes"
 "context"
 "crypto/sha256"
 "database/sql"
 "encoding/hex"
 "encoding/json"
 "os"
 "path/filepath"
 "runtime"
 "testing"
)

func captureParent(t *testing.T) string {
 t.Helper()
 p := t.TempDir()
 if err := os.Chmod(p, 0700); err != nil { t.Fatal(err) }
 return p
}

func TestCaptureSnapshotStandaloneWALAndUnique(t *testing.T) {
 _, r, _ := snapshotFixture(t)
 if _, err := r.db.Exec("PRAGMA wal_autocheckpoint=0; CREATE TABLE capture_marker(value TEXT); INSERT INTO capture_marker VALUES('committed-in-wal')"); err != nil { t.Fatal(err) }
 parent := captureParent(t)
 sentinel := filepath.Join(parent,"state.db")
 if err := os.WriteFile(sentinel, []byte("unrelated"),0600); err != nil { t.Fatal(err) }
 first, err := r.CaptureSnapshot(ctx,parent,"")
 if err != nil { t.Fatal(err) }
 before, err := os.ReadFile(first.Path)
 if err != nil { t.Fatal(err) }
 sum := sha256.Sum256(before)
 if first.Bytes != int64(len(before)) || first.SHA256 != hex.EncodeToString(sum[:]) { t.Fatal("capture digest/size mismatch") }
 if first.Inspection.SchemaVersion != 7 || first.Inspection.Users != 2 || first.Inspection.Credentials != 2 || first.Inspection.PendingOperations != 0 { t.Fatalf("aggregate: %+v",first.Inspection) }
 encoded,err := json.Marshal(first)
 if err != nil { t.Fatal(err) }
 if bytes.Contains(encoded,[]byte(first.Path)) { t.Fatal("local path exposed in JSON") }
 if runtime.GOOS != "windows" {
  for path, mode := range map[string]os.FileMode{first.Path:0600,filepath.Dir(first.Path):0700} {
   info,err := os.Stat(path); if err != nil { t.Fatal(err) }; if info.Mode().Perm()!=mode { t.Fatalf("permissions %s: %o",path,info.Mode().Perm()) }
  }
 }
 // Read the captured file directly, without Registry.Open or schema migrations.
 copied,err := sql.Open("sqlite3",first.Path+"?mode=ro&immutable=1")
 if err != nil { t.Fatal(err) }; defer copied.Close()
 var marker string
 if err = copied.QueryRow("SELECT value FROM capture_marker").Scan(&marker); err != nil || marker!="committed-in-wal" { t.Fatalf("committed WAL data absent: %q %v",marker,err) }
 second,err := r.CaptureSnapshot(ctx,parent,"")
 if err != nil { t.Fatal(err) }; if second.Path==first.Path || filepath.Dir(second.Path)==filepath.Dir(first.Path) { t.Fatal("capture directory reused") }
 after,err := os.ReadFile(first.Path); if err != nil || !bytes.Equal(before,after) { t.Fatal("previous capture changed",err) }
 untouched,err := os.ReadFile(sentinel); if err != nil || string(untouched)!="unrelated" { t.Fatal("unrelated file overwritten",err) }
}

func TestCaptureSnapshotRefusalCleansChild(t *testing.T) {
 for _, name := range []string{"cancelled","unfinished","wrong-own-kind","own-running"} {
 t.Run(name,func(t *testing.T){
  _,r,rec := snapshotFixture(t)
  parent:=captureParent(t)
  callCtx:=ctx
  own:=""
  if name=="cancelled" { c,cancel:=context.WithCancel(ctx); cancel(); callCtx=c } else {
   if _,err:=r.db.Exec("UPDATE operations SET status='running' WHERE id=?",rec.OperationID); err!=nil { t.Fatal(err) }
   if name!="unfinished" { own=rec.OperationID }
   if name=="own-running" { if _,err:=r.db.Exec("UPDATE operations SET kind='backup.create' WHERE id=?",rec.OperationID);err!=nil {t.Fatal(err)} }
  }
  result,err:=r.CaptureSnapshot(callCtx,parent,own)
  if name=="own-running" { if err!=nil {t.Fatal(err)}; if result.Inspection.PendingOperations!=0 {t.Fatal("own operation counted")}; return }
  if err==nil {t.Fatal("unsafe capture accepted")}
  entries,err:=os.ReadDir(parent);if err!=nil {t.Fatal(err)};if len(entries)!=0 {t.Fatal("failed capture left child")}
 })
 }
}

func TestCaptureSnapshotUnsafeParent(t *testing.T) {
 if runtime.GOOS=="windows" {t.Skip("POSIX permission and symlink policy")}
 for _,name:=range []string{"public","symlink"} {t.Run(name,func(t *testing.T){
  _,r,_:=snapshotFixture(t)
  parent:=captureParent(t)
  if name=="public" {if err:=os.Chmod(parent,0755);err!=nil {t.Fatal(err)}} else {link:=filepath.Join(captureParent(t),"link");if err:=os.Symlink(parent,link);err!=nil {t.Fatal(err)};parent=link}
  if _,err:=r.CaptureSnapshot(ctx,parent,"");err==nil {t.Fatal("unsafe parent accepted")}
 })}
}

func TestCaptureSnapshotOversizeCleansChild(t *testing.T) {
 _,r,_:=snapshotFixture(t)
 if _,err:=r.db.Exec("CREATE TABLE snapshot_padding(payload BLOB)");err!=nil {t.Fatal(err)}
 if _,err:=r.db.Exec("INSERT INTO snapshot_padding(payload) VALUES(zeroblob(?))",SnapshotMaxBytes+4096);err!=nil {t.Fatal(err)}
 parent:=captureParent(t)
 sentinel:=filepath.Join(parent,"unrelated")
 if err:=os.WriteFile(sentinel,[]byte("preserve"),0600);err!=nil {t.Fatal(err)}
 if _,err:=r.CaptureSnapshot(ctx,parent,"");err==nil {t.Fatal("oversized snapshot accepted")}
 entries,err:=os.ReadDir(parent);if err!=nil {t.Fatal(err)}
 if len(entries)!=1 || entries[0].Name()!="unrelated" {t.Fatal("failed oversized capture left child or removed sentinel")}
 content,err:=os.ReadFile(sentinel);if err!=nil || string(content)!="preserve" {t.Fatal("sentinel changed",err)}
}
