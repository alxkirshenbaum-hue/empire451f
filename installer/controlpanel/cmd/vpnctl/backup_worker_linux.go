//go:build linux

package main

import (
 "bytes"
 "context"
 "encoding/json"
 "errors"
	"flag"
	"fmt"
	"io"
 "os"
 "os/exec"
 "path/filepath"
 "syscall"
 "time"

 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
)

func configureBackup(args []string,out,stderr io.Writer) int {
 f:=flag.NewFlagSet("backup configure",flag.ContinueOnError);f.SetOutput(io.Discard);installation:=f.String("installation","","Installation ID");run:=f.String("owner-run","","Accepted writer run")
 if f.Parse(args)!=nil||f.NArg()!=0||!installationID.MatchString(*installation)||!status.ValidID(*run){fmt.Fprintln(stderr,"Expected installation and owner run");return 2};if os.Geteuid()!=0{fmt.Fprintln(stderr,"Run as root on the entry");return 3}
 p,e:=readWorkerPolicy(filepath.Join("/etc/vpn-control","worker-"+*installation+".json"),*installation,*run);if e!=nil||p.BackupHelper==""{fmt.Fprintln(stderr,"Root-controlled backup policy unavailable");return 4}
 _,e=withOwnedInstallation(filepath.Join("/var/lib/empire-vpn",*installation),"/etc/empire-vpn","/run/lock/empire-vpn.lock","/var/lib/vpn-control",*run,func(ctx context.Context,r *storage.Registry)(storage.Receipt,error){
  rec,err:=artifactCommand(ctx,p.BackupHelper,map[string]string{"action":"recipient","public_key_path":p.BackupRecipient});if err!=nil{return storage.Receipt{},err};return storage.Receipt{},r.ConfigureBackups(ctx,rec.KeyFingerprint)
 });if e!=nil{fmt.Fprintln(stderr,"Cannot configure backup recipient");return 4};fmt.Fprintln(out,"Public backup recipient configured; keep the private key off the server");return 0
}

func backupRootDirectory(path string) error {
 if !filepath.IsAbs(path){return storage.ErrInvalidMetadata};resolved,e:=filepath.EvalSymlinks(path);if e!=nil||resolved!=path{return storage.ErrInvalidMetadata};i,e:=os.Lstat(path);if e!=nil{return e};s,ok:=i.Sys().(*syscall.Stat_t);if !ok||!i.IsDir()||s.Uid!=0||i.Mode().Perm()&0027!=0{return storage.ErrInvalidMetadata};return nil
}

type artifactReceipt struct { SHA256 string `json:"sha256"`;SizeBytes int64 `json:"size_bytes"`;KeyFingerprint string `json:"key_fingerprint"` }

type boundedReceipt struct {bytes.Buffer}
func(b *boundedReceipt)Write(p []byte)(int,error){if len(p)>4096-b.Len(){return 0,storage.ErrInvalidMetadata};return b.Buffer.Write(p)}

func artifactCommand(ctx context.Context,helper string,request any)(artifactReceipt,error) {
 var rec artifactReceipt
 data,e:=json.Marshal(request);if e!=nil||len(data)>8192{return rec,storage.ErrInvalidMetadata};defer clear(data)
 ctx,cancel:=context.WithTimeout(ctx,45*time.Second);defer cancel()
 cmd:=exec.CommandContext(ctx,"python3","-B",helper);cmd.Stdin=bytes.NewReader(data)
 // The helper emits only a small receipt; no exception/path/secret diagnostics.
 var out boundedReceipt;cmd.Stdout=&out
 if e=cmd.Run();e!=nil{return rec,errors.New("artifact operation requires reconciliation")}
 if out.Len()>4096||json.Unmarshal(out.Bytes(),&rec)!=nil{return rec,storage.ErrInvalidMetadata}
 return rec,nil
}

// Called only from the existing worker's common writer callback. A waiting
// owner verification returns immediately, releasing both lock and process.
func(w *createCaddyWorker)applyMaintenance(ctx context.Context,reg *storage.Registry,j storage.MaintenanceJob)(storage.Receipt,error) {
 rec:=storage.Receipt{OperationID:j.OperationID}
 if j.Phase=="verifying"&&j.Action=="backup.verify" {return rec,nil}
 if j.Phase!="queued" {
  if j.Phase=="running"||j.Phase=="verifying" {return rec,errors.Join(storage.ErrJournalConflict,reg.Transition(ctx,j.OperationID,j.Phase,"reconcile_required"))};return rec,storage.ErrJournalConflict
 }
 if e:=reg.Transition(ctx,j.OperationID,"queued","running");e!=nil{return rec,e};j.Phase="running"
 if j.Action=="backup.verify" {return rec,reg.StartMaintenanceVerify(ctx,j)}
 if j.Action!="backup.create" {return rec,errors.Join(storage.ErrInvalidMetadata,reg.Transition(ctx,j.OperationID,"running","failed"))}
 e:=w.createBackup(ctx,reg,j)
 if e!=nil {
  current,readErr:=reg.NextMaintenance(ctx,w.run)
  if readErr==nil&&(current.Phase=="running"||current.Phase=="verifying"){return rec,errors.Join(e,reg.Transition(ctx,j.OperationID,current.Phase,"reconcile_required"))}
  return rec,errors.Join(e,readErr)
 }
 return rec,nil
}

func(w *createCaddyWorker)createBackup(ctx context.Context,reg *storage.Registry,j storage.MaintenanceJob)(resultErr error) {
 p:=w.backupPolicy
 if p==nil||p.BackupHelper=="" {return storage.ErrInvalidMetadata}
 for _,f:=range []string{p.BackupHelper,p.BackupRecipient} {if e:=rootFile(f,false);e!=nil{return e}}
 for _,d:=range []string{p.BackupDirectory,p.BackupWork} {if e:=backupRootDirectory(d);e!=nil{return e}}
 // Plaintext staging must not be visible even to the unprivileged API UID.
 i,e:=os.Stat(p.BackupWork);if e!=nil||i.Mode().Perm()&0077!=0{return storage.ErrInvalidMetadata}
 recipient,e:=artifactCommand(ctx,p.BackupHelper,map[string]string{"action":"recipient","public_key_path":p.BackupRecipient});if e!=nil{return e};if recipient.KeyFingerprint!=j.KeyID{return storage.ErrJournalConflict}
 work:=filepath.Join(p.BackupWork,j.OperationID);if e=os.Mkdir(work,0700);e!=nil{return e}
 defer func(){resultErr=errors.Join(resultErr,os.RemoveAll(work))}()
 archive,e:=createInstallationArchive(ctx,reg,w.state,w.config,w.panel,w.run,work,j.OperationID);if e!=nil{return e}
 now:=time.Now();if e=reg.AppendStep(ctx,j.OperationID,"running",storage.Checkpoint{Number:1,Name:"snapshot",State:"succeeded",Started:now,Finished:now,AfterHash:archive.SHA256});e!=nil{return e}
 output:=filepath.Join(p.BackupDirectory,j.BackupID+".jwe")
 sealed,e:=artifactCommand(ctx,p.BackupHelper,map[string]string{"action":"seal","source":archive.Path,"public_key_path":p.BackupRecipient,"output":output});if e!=nil{return e}
 if sealed.KeyFingerprint!=j.KeyID{return storage.ErrJournalConflict}
 // Directory remains root-owned and group-readable only for ciphertext.
 if e=os.Chown(output,0,981);e!=nil{return e};if e=os.Chmod(output,0640);e!=nil{return e}
 if e=os.RemoveAll(work);e!=nil{return e}
 if e=reg.Transition(ctx,j.OperationID,"running","verifying");e!=nil{return e}
 if e=reg.RegisterBackup(ctx,j,output,sealed.SHA256,sealed.SizeBytes,archive.Generation,archive.ManifestSHA256);e!=nil{return e}
 return nil
}
