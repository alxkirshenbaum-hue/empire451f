package main

import (
 "crypto/sha256"
 "encoding/hex"
 "fmt"
 "io"
 "net/http"
 "os"
 "path/filepath"

 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/status"
 "github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/storage"
)

// Only the authenticated owner can access ciphertext or submit an attestation.
// The private recipient key is never accepted by this service.
func maintenanceRoutes(mux *http.ServeMux, registry *storage.Registry, run string, owner func(bool,func(http.ResponseWriter,*http.Request,string)) http.HandlerFunc) {
 queue := func(w http.ResponseWriter,r *http.Request,actor string,q storage.MaintenanceRequest) {
  j,err:=registry.QueueMaintenance(r.Context(),run,actor,r.Header.Get("Idempotency-Key"),q)
  if err!=nil {panelError(w,err);return};panelJSON(w,202,j)
 }
 mux.HandleFunc("POST /api/v1/backups",owner(true,func(w http.ResponseWriter,r *http.Request,actor string){
  var q struct{Label string `json:"label"`};if !panelBody(w,r,&q){return};queue(w,r,actor,storage.MaintenanceRequest{Action:"backup.create",Label:q.Label})
 }))
 mux.HandleFunc("GET /api/v1/backups/{id}",owner(false,func(w http.ResponseWriter,r *http.Request,_ string){
  if !status.ValidID(r.PathValue("id")){panelError(w,storage.ErrInvalidMetadata);return};b,e:=registry.BackupInfo(r.Context(),r.PathValue("id"));if e!=nil{panelError(w,e);return};panelJSON(w,200,b)
 }))
 mux.HandleFunc("GET /api/v1/backups/{id}/download",owner(false,func(w http.ResponseWriter,r *http.Request,_ string){
  if !status.ValidID(r.PathValue("id")){panelError(w,storage.ErrInvalidMetadata);return};b,e:=registry.GetBackupInternal(r.Context(),r.PathValue("id"));if e!=nil{panelError(w,e);return}
  if b.Status=="deleted"||b.Status=="expired" {http.Error(w,"Backup is unavailable",410);return}
  // Root publishes immutable files. Check the actual descriptor before serving.
  resolved,e:=filepath.EvalSymlinks(b.EncryptedPath);if e!=nil||resolved!=b.EncryptedPath{panelError(w,storage.ErrJournalConflict);return}
  f,e:=os.Open(b.EncryptedPath);if e!=nil{panelError(w,e);return};defer f.Close();info,e:=f.Stat()
  if e!=nil||!info.Mode().IsRegular()||info.Mode().Perm()&0022!=0||info.Size()!=b.SizeBytes||b.SizeBytes<1||b.SizeBytes>48*1024*1024{panelError(w,storage.ErrJournalConflict);return}
  h:=sha256.New();n,e:=io.Copy(h,io.LimitReader(f,48*1024*1024+1));if e!=nil||n!=b.SizeBytes||hex.EncodeToString(h.Sum(nil))!=b.SHA256{panelError(w,storage.ErrJournalConflict);return}
  if _,e=f.Seek(0,io.SeekStart);e!=nil{panelError(w,e);return}
  w.Header().Set("Content-Type","application/jose");w.Header().Set("Cache-Control","no-store");w.Header().Set("X-Content-Type-Options","nosniff");w.Header().Set("Content-Disposition",fmt.Sprintf("attachment; filename=\"%s.jwe\"",b.ID));w.Header().Set("Content-Length",fmt.Sprint(b.SizeBytes));_,_=io.Copy(w,io.LimitReader(f,b.SizeBytes))
 }))
 mux.HandleFunc("POST /api/v1/backups/{id}/verify",owner(true,func(w http.ResponseWriter,r *http.Request,actor string){
  var q struct{SHA256 string `json:"sha256"`};if !panelBody(w,r,&q){return};queue(w,r,actor,storage.MaintenanceRequest{Action:"backup.verify",BackupID:r.PathValue("id"),ExpectedHash:q.SHA256})
 }))
 mux.HandleFunc("POST /api/v1/operations/{id}/backup-verification",owner(true,func(w http.ResponseWriter,r *http.Request,actor string){
  var report storage.VerificationReport;if !status.ValidID(r.PathValue("id")){panelError(w,storage.ErrInvalidMetadata);return};if !panelBody(w,r,&report){return};if e:=registry.CompleteBackupVerify(r.Context(),actor,r.PathValue("id"),report);e!=nil{panelError(w,e);return};panelJSON(w,200,map[string]string{"operation_id":r.PathValue("id"),"evidence_source":"OWNER_ATTESTATION"})
 }))
 mux.HandleFunc("POST /api/v1/operations/{id}/cancel",owner(true,func(w http.ResponseWriter,r *http.Request,actor string){
  var q struct{};if !status.ValidID(r.PathValue("id")){panelError(w,storage.ErrInvalidMetadata);return};if !panelBody(w,r,&q){return};if e:=registry.CancelMaintenance(r.Context(),actor,r.PathValue("id"));e!=nil{panelError(w,e);return};panelJSON(w,200,map[string]string{"operation_id":r.PathValue("id"),"status":"cancelled"})
 }))
 mux.HandleFunc("POST /api/v1/backups/prune",owner(true,func(w http.ResponseWriter,r *http.Request,actor string){
  var q struct{Keep int `json:"keep"`;DryRun bool `json:"dry_run"`;ExpectedState string `json:"expected_state"`};if !panelBody(w,r,&q){return};if q.DryRun{p,e:=registry.PrunePlan(r.Context(),q.Keep);if e!=nil{panelError(w,e);return};panelJSON(w,200,p);return};queue(w,r,actor,storage.MaintenanceRequest{Action:"backup.prune",Keep:q.Keep,ExpectedHash:q.ExpectedState})
 }))
}
