package storage

import (
 "context"
 "crypto/sha256"
 "database/sql"
 "encoding/hex"
 "errors"
 "io"
 "os"
 "path/filepath"

 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// RotateVaultCopy prepares a NEW offline candidate without modifying the source
// registry or its key. Activation requires a separately approved controlled swap
// of the complete DB/key pair while the mutating control plane is stopped.
// The caller protects both staging and new key custody; this is not a Web apply.
func(r *Registry)RotateVaultCopy(ctx context.Context,directory,ownID string,next *vault.Vault)(out SnapshotCapture,resultErr error){
 if next==nil{return out,ErrVaultKey}
 captured,e:=r.CaptureSnapshot(ctx,directory,ownID);if e!=nil{return out,e};accepted:=false
 defer func(){if !accepted{resultErr=errors.Join(resultErr,os.RemoveAll(filepath.Dir(captured.Path)))}}()
 db,e:=sql.Open("sqlite3",snapshotURI(captured.Path)+"?mode=rw&_journal_mode=DELETE&_foreign_keys=on&_synchronous=FULL&_txlock=immediate");if e!=nil{return out,e};db.SetMaxOpenConns(1)
 candidate:=&Registry{db:db,vault:r.vault,keyVersion:r.keyVersion}
 e=func()error{
  tx,err:=db.BeginTx(ctx,nil);if err!=nil{return err};defer tx.Rollback()
  if err=candidate.verifyVaultIdentity(ctx,tx);err!=nil{return err}
  rows,err:=tx.QueryContext(ctx,"SELECT id,user_id,secret_version,key_version,nonce,ciphertext FROM credentials ORDER BY id");if err!=nil{return err}
  for rows.Next(){
   var id,user string;var secretVersion,keyVersion uint64;var nonce,ciphertext []byte
   if err=rows.Scan(&id,&user,&secretVersion,&keyVersion,&nonce,&ciphertext);err!=nil{break}
   plain,decryptErr:=r.vault.Decrypt(vault.Binding{UserID:user,SecretVersion:secretVersion,KeyVersion:keyVersion},nonce,ciphertext);if decryptErr!=nil{err=ErrVaultKey;clear(plain);break}
   freshNonce,freshCipher,encryptErr:=next.Encrypt(vault.Binding{UserID:user,SecretVersion:secretVersion,KeyVersion:uint64(r.keyVersion+1)},plain);clear(plain);if encryptErr!=nil{err=encryptErr;break}
   _,err=tx.ExecContext(ctx,"UPDATE credentials SET key_version=?,nonce=?,ciphertext=? WHERE id=?",r.keyVersion+1,freshNonce,freshCipher,id);if err!=nil{break}
  }
  err=errors.Join(err,rows.Err(),rows.Close());if err!=nil{return err}
  nonce,ciphertext,err:=next.Encrypt(vault.Binding{UserID:"!registry-key-check",SecretVersion:1,KeyVersion:uint64(r.keyVersion+1)},vault.PlainSecret("vpn-control registry key v1"));if err!=nil{return err}
  if _,err=tx.ExecContext(ctx,"UPDATE vault_identity SET key_version=?,nonce=?,ciphertext=? WHERE singleton=1",r.keyVersion+1,nonce,ciphertext);err!=nil{return err}
  if _,err=tx.ExecContext(ctx,"INSERT INTO audit_runs(id,script_version,started_at,finished_at,summary) VALUES(?,'vault-copy-v1',CURRENT_TIMESTAMP,CURRENT_TIMESTAMP,'Offline vault rotation candidate; source unchanged')",id());err!=nil{return err}
  return tx.Commit()
 }()
 if e==nil{candidate.vault=next;candidate.keyVersion=r.keyVersion+1;captured.Inspection,e=candidate.InspectSnapshot(ctx,ownID)}
 e=errors.Join(e,db.Close());if e!=nil{return out,e}
 for _,suffix:=range []string{"-wal","-shm","-journal"}{if _,e=os.Lstat(captured.Path+suffix);!errors.Is(e,os.ErrNotExist){return out,ErrSnapshotState}}
 f,e:=os.OpenFile(captured.Path,os.O_RDWR,0);if e!=nil{return out,e};h:=sha256.New();n,e:=io.Copy(h,io.LimitReader(f,SnapshotMaxBytes+1));if e==nil{e=f.Sync()};e=errors.Join(e,f.Close());if e!=nil{return out,e};if n>SnapshotMaxBytes{return out,ErrSnapshotState};if e=snapshotSyncDirectory(filepath.Dir(captured.Path));e!=nil{return out,e}
 captured.Bytes=n;captured.SHA256=hex.EncodeToString(h.Sum(nil));accepted=true;return captured,nil
}
