//go:build linux

package main

import (
 "bytes"
 "context"
 "crypto/sha256"
 "database/sql"
 "encoding/json"
 "errors"
 "fmt"
 "os"
 "path/filepath"
 "testing"

 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

func TestInstallationSnapshotBinding(t *testing.T) {
 for _, scenario := range []string{"valid", "file-drift", "missing-managed", "prepared", "owner", "cutover", "key", "pending.json", "panel-auth-pending.json", "symlink"} {
 t.Run(scenario, func(t *testing.T) {
 root:=t.TempDir(); state:=filepath.Join(root,"state"); config:=filepath.Join(root,"etc"); panel:=filepath.Join(root,"panel"); dest:=filepath.Join(root,"captures")
 for _, p:=range []string{state,filepath.Join(config,"lab"),panel,dest} { if err:=os.MkdirAll(p,0700); err!=nil {t.Fatal(err)} }
 put:=func(p string,b []byte){t.Helper();if err:=os.WriteFile(p,b,0600);err!=nil{t.Fatal(err)}}
 hash:=func(b []byte)string{return fmt.Sprintf("%x",sha256.Sum256(b))}
 run:="a9b5c248-884a-40f0-823a-4dae9a541e3b"
 auth:=filepath.Join(config,"lab","auth.caddy"); managed:=filepath.Join(config,"lab","Caddyfile")
 put(auth,[]byte("fixture auth"));put(managed,[]byte("fixture managed"))
 meta:=map[string]any{"config":map[string]string{"id":"lab"},"files":map[string]string{managed:hash([]byte("fixture managed"))},"panel_run_id":run,"panel_generation":1,"panel_auth_hash":hash([]byte("fixture auth"))}
 raw,_:=json.Marshal(meta);put(filepath.Join(state,"manifest.json"),raw)
 key:=bytes.Repeat([]byte{19},32);put(filepath.Join(panel,"vault.key"),key);cipher,_:=vault.New(key)
 reg,err:=storage.Open(context.Background(),filepath.Join(panel,"state.db"),cipher,1);if err!=nil{t.Fatal(err)};reg.Close()
 db,err:=sql.Open("sqlite3",filepath.Join(panel,"state.db"));if err!=nil{t.Fatal(err)};defer db.Close()
 exec:=func(q string,args ...any){t.Helper();if _,err:=db.Exec(q,args...);err!=nil{t.Fatal(err)}}
 exec("INSERT INTO legacy_migration_runs(id,phase,source_hashes,started_at,status) VALUES(?,'verified_cutover','{}','now','verified_cutover')",run)
 nonce,encrypted,err:=cipher.Encrypt(vault.Binding{UserID:"master",SecretVersion:1,KeyVersion:1},vault.PlainSecret("fixture-master"));if err!=nil{t.Fatal(err)}
 exec("INSERT INTO users(id,login,display_name,kind,protected,source,status,created_at,updated_at) VALUES('master','master_user','master_user','service',1,'legacy_import','active',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)")
 exec("INSERT INTO credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,key_version,created_at) VALUES('credential','master',1,?,?,?,1,CURRENT_TIMESTAMP)",vault.Algorithm,nonce,encrypted)
 exec("INSERT INTO user_current_credentials VALUES('master','credential',CURRENT_TIMESTAMP)")
 sentry:=filepath.Join(dest,"sentry");put(sentry,[]byte("keep"))
 switch scenario {
 case "file-drift":put(managed,[]byte("drift"))
 case "missing-managed":if err:=os.Remove(managed);err!=nil{t.Fatal(err)}
 case "prepared":dir:=filepath.Join(state,"panel-operations","stray-operation");if err:=os.MkdirAll(dir,0700);err!=nil{t.Fatal(err)};put(filepath.Join(dir,"prepared.json"),[]byte("{}"))
 case "owner":run="wrong-owner"
 case "cutover":exec("UPDATE legacy_migration_runs SET phase='importing',status='copy_handed_off'")
 case "key":put(filepath.Join(panel,"vault.key"),bytes.Repeat([]byte{20},32))
 case "pending.json","panel-auth-pending.json":put(filepath.Join(state,scenario),[]byte("{}"))
 case "symlink":os.Remove(managed);if err:=os.Symlink(sentry,managed);err!=nil{t.Fatal(err)}
 }
 got,err:=captureInstallationSnapshot(state,config,filepath.Join(root,"lock"),panel,run,dest,"")
 if scenario=="valid" {
 if err!=nil{t.Fatal(err)}
 if got.Generation!=1||got.OwnerRun!=run{t.Fatalf("unbound metadata: %+v",got)}
 for _,path:=range []string{filepath.Join(state,"manifest.json"),auth,managed,filepath.Join(panel,"vault.key")} { data,e:=os.ReadFile(path);if e!=nil{t.Fatal(e)};if got.Files[path]!=hash(data){t.Fatalf("unbound file digest %s: %q",path,got.Files[path])} }
 if got.Capture.Inspection.SchemaVersion!=7||got.Capture.Inspection.Users!=1{t.Fatalf("unexpected inspection: %+v",got.Capture.Inspection)}
 b,e:=os.ReadFile(got.Capture.Path);if e!=nil||hash(b)!=got.Capture.SHA256{t.Fatalf("capture hash: %v",e)}
 if filepath.Dir(got.Capture.Path)==dest{t.Fatal("capture lacks private child")}
 }else{
 if err==nil{t.Fatal("unsafe installation accepted")}
 if scenario=="missing-managed"&&!errors.Is(err,storage.ErrLegacyDrift){t.Fatalf("missing managed file: %v; want legacy drift",err)}
 entries,e:=os.ReadDir(dest);if e!=nil||len(entries)!=1||entries[0].Name()!="sentry"{t.Fatalf("failure leaked capture: %v %v",entries,e)}
 }
 b,e:=os.ReadFile(sentry);if e!=nil||string(b)!="keep"{t.Fatal("changed sibling sentry",e)}
 })
 }
}
