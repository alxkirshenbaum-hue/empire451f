package storage

import (
 "context"
 "database/sql"
 "encoding/json"
 "errors"
 "path/filepath"
 "regexp"
 "strings"
 "time"
)

type MaintenanceRequest struct { Action, BackupID, Label, Scope, ExpectedHash string; Keep int; DryRun bool }
type MaintenanceJob struct { OperationID, BackupID, Action, OwnerRun, Actor, KeyID, ExpectedHash, Label, Phase string; Request MaintenanceRequest }
type MaintenanceBackup struct { ID, CreatedAt, SHA256, Status, VerifiedAt, Label, KeyID, ManifestSHA256, OwnerRun string; SizeBytes, SourceGeneration int64; EncryptedPath string `json:"-"` }
type VerificationChecks struct { EnvelopeAuthenticated, Manifest, DatabaseIntegrity, SchemaChecksums, VaultPairing, ExternalReferences bool }
type RestoreProof struct { OwnerLogin, OldProfileFresh, RevokedRejected, CaddyValidated, RollbackPassed bool }
type VerificationReport struct { BackupID, Outcome, CipherSHA256, KeyID, VerifierRevision string; Checks VerificationChecks; RestoreProof *RestoreProof `json:",omitempty"` }
type MaintenancePrunePlan struct { IDs []string; ExpectedStateHash string }
var uuidMaintenance = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
var revisionMaintenance = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
var keyMaintenance = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,128}$`)
func maintenanceStamp() string { return time.Now().UTC().Format(time.RFC3339Nano) }
func validMaintenance(q MaintenanceRequest) bool {
 if len(q.Label)>128 || strings.ContainsAny(q.Label,"\x00\r\n") || q.Keep<0 || q.Keep>1000 { return false }
 switch q.Action { case "backup.create": return q.BackupID=="" && q.ExpectedHash=="" && q.Scope=="" && q.Keep==0 && !q.DryRun
 case "backup.verify": return uuidMaintenance.MatchString(q.BackupID) && hashPattern.MatchString(q.ExpectedHash) && q.Scope=="" && q.Keep==0 && !q.DryRun
 case "backup.prune": return q.BackupID=="" && q.Scope=="" && (q.ExpectedHash=="" || hashPattern.MatchString(q.ExpectedHash))
 case "audit.run": return q.BackupID=="" && q.ExpectedHash=="" && q.Scope=="safe" && q.Keep==0
 }; return false
}
func (r *Registry) ConfigureBackups(ctx context.Context,keyID string) error { if !keyMaintenance.MatchString(keyID) { return ErrInvalidMetadata }; _,e:=r.db.ExecContext(ctx,`INSERT INTO backup_configuration VALUES(1,?,1) ON CONFLICT(singleton) DO UPDATE SET key_id=excluded.key_id,enabled=1`,keyID); return e }
func (r *Registry) BackupConfigured(ctx context.Context)(bool,error) { var b bool; e:=r.db.QueryRowContext(ctx,`SELECT enabled FROM backup_configuration WHERE singleton=1`).Scan(&b); if errors.Is(e,sql.ErrNoRows){return false,nil};return b,e }
func MaintenanceBlocked(ctx context.Context, tx *sql.Tx) error { var n int; e:=tx.QueryRowContext(ctx,`SELECT count(*) FROM operations o JOIN maintenance_intents m ON m.operation_id=o.id WHERE o.status NOT IN ('succeeded','failed','cancelled','rolled_back')`).Scan(&n);if e!=nil{return e};if n>0{return ErrOperationInProgress};return nil }
const maintenanceColumns=`o.id,COALESCE(m.backup_id,''),o.kind,m.owner_run,o.actor_id,m.key_id,m.expected_hash,m.label,o.status,m.request_json`
func scanMaintenance(row interface{Scan(...any) error})(j MaintenanceJob,e error){var raw string;e=row.Scan(&j.OperationID,&j.BackupID,&j.Action,&j.OwnerRun,&j.Actor,&j.KeyID,&j.ExpectedHash,&j.Label,&j.Phase,&raw);if e!=nil{return}; e=json.Unmarshal([]byte(raw),&j.Request);if e==nil && (!validMaintenance(j.Request)||j.Request.Action!=j.Action){e=ErrInvalidMetadata};return}
func (r *Registry) QueueMaintenance(ctx context.Context,run,actor,key string,q MaintenanceRequest)(MaintenanceJob,error){
 z:=MaintenanceJob{};if run==""||len(run)>128||actor==""||len(actor)>128||key==""||len(key)>128||!validMaintenance(q){return z,ErrInvalidMetadata}
 raw,_:=json.Marshal(struct{Run string;Request MaintenanceRequest}{run,q}); h:=digest(raw)
 tx,e:=r.db.BeginTx(ctx,nil);if e!=nil{return z,e};defer tx.Rollback()
 var oldHash,oldID string;e=tx.QueryRowContext(ctx,`SELECT id,request_hash FROM operations WHERE actor_id=? AND idempotency_key=?`,actor,key).Scan(&oldID,&oldHash)
 if e==nil {if oldHash!=h{return z,ErrIdempotencyConflict};return scanMaintenance(tx.QueryRowContext(ctx,`SELECT `+maintenanceColumns+` FROM operations o JOIN maintenance_intents m ON m.operation_id=o.id WHERE o.id=?`,oldID))};if !errors.Is(e,sql.ErrNoRows){return z,e}
 if e=requireVerifiedCutover(ctx,tx,run);e!=nil{return z,e}
 var keyID string;e=tx.QueryRowContext(ctx,`SELECT key_id FROM backup_configuration WHERE singleton=1 AND enabled=1`).Scan(&keyID);if e!=nil{return z,e}
 var n int;if e=tx.QueryRowContext(ctx,`SELECT count(*) FROM operations WHERE status NOT IN ('succeeded','failed','cancelled','rolled_back')`).Scan(&n);e!=nil{return z,e};if n!=0{return z,ErrOperationInProgress}
 bid:=q.BackupID;if q.Action=="backup.create"{bid=id()}
 if q.Action=="backup.verify"{var sha,status string;if e=tx.QueryRowContext(ctx,`SELECT b.sha256,d.key_id,b.status FROM backups b JOIN backup_details d ON d.backup_id=b.id WHERE b.id=?`,bid).Scan(&sha,&keyID,&status);e!=nil{return z,e};if sha!=q.ExpectedHash || status=="deleted"||status=="expired"{return z,ErrJournalConflict}}
 j:=MaintenanceJob{OperationID:id(),BackupID:bid,Action:q.Action,OwnerRun:run,Actor:actor,KeyID:keyID,ExpectedHash:q.ExpectedHash,Label:q.Label,Phase:"queued",Request:q};request,_:=json.Marshal(q)
 _,e=tx.ExecContext(ctx,`INSERT INTO operations(id,actor_id,kind,target_type,target_id,status,idempotency_key,request_hash,correlation_id,created_at) VALUES(?,?,?,'backup',?,'queued',?,?,?,?)`,j.OperationID,actor,q.Action,bid,key,h,j.OperationID,maintenanceStamp());if e!=nil{return z,e}
 _,e=tx.ExecContext(ctx,`INSERT INTO maintenance_intents(operation_id,owner_run,request_json,label,backup_id,key_id,expected_hash) VALUES(?,?,?,?,?,?,?)`,j.OperationID,run,string(request),q.Label,bid,keyID,q.ExpectedHash);if e!=nil{return z,e};e=tx.Commit();return j,e
}
func (r *Registry) NextMaintenance(ctx context.Context,run string)(MaintenanceJob,error){return scanMaintenance(r.db.QueryRowContext(ctx,`SELECT `+maintenanceColumns+` FROM operations o JOIN maintenance_intents m ON m.operation_id=o.id WHERE m.owner_run=? AND o.status NOT IN ('succeeded','failed','cancelled','rolled_back') ORDER BY o.created_at,o.id LIMIT 1`,run))}
const backupColumns=`b.id,b.created_at,b.sha256,b.status,COALESCE(b.verified_at,''),d.label,d.key_id,d.manifest_sha256,d.owner_run,b.size_bytes,b.source_generation,b.encrypted_path`
func scanBackup(row interface{Scan(...any)error})(b MaintenanceBackup,e error){e=row.Scan(&b.ID,&b.CreatedAt,&b.SHA256,&b.Status,&b.VerifiedAt,&b.Label,&b.KeyID,&b.ManifestSHA256,&b.OwnerRun,&b.SizeBytes,&b.SourceGeneration,&b.EncryptedPath);return}
func(r *Registry)GetBackupInternal(ctx context.Context,bid string)(MaintenanceBackup,error){return scanBackup(r.db.QueryRowContext(ctx,`SELECT `+backupColumns+` FROM backups b JOIN backup_details d ON d.backup_id=b.id WHERE b.id=?`,bid))}
func(r *Registry)BackupInfo(ctx context.Context,bid string)(MaintenanceBackup,error){b,e:=r.GetBackupInternal(ctx,bid);b.EncryptedPath="";return b,e}
func(r *Registry)RegisterBackup(ctx context.Context,j MaintenanceJob,path,sha string,size,generation int64,manifestSHA string)error{
 if !filepath.IsAbs(path)||!hashPattern.MatchString(sha)||!hashPattern.MatchString(manifestSHA)||size<=0||generation<0{return ErrInvalidMetadata}
 tx,e:=r.db.BeginTx(ctx,nil);if e!=nil{return e};defer tx.Rollback();saved,e:=scanMaintenance(tx.QueryRowContext(ctx,`SELECT `+maintenanceColumns+` FROM operations o JOIN maintenance_intents m ON m.operation_id=o.id WHERE o.id=?`,j.OperationID));if e!=nil{return e};if saved.Action!="backup.create"||saved.BackupID!=j.BackupID||saved.OwnerRun!=j.OwnerRun||saved.KeyID!=j.KeyID{return ErrJournalConflict}
 old,e:=scanBackup(tx.QueryRowContext(ctx,`SELECT `+backupColumns+` FROM backups b JOIN backup_details d ON d.backup_id=b.id WHERE d.operation_id=?`,j.OperationID));if e==nil{if old.ID==j.BackupID&&old.EncryptedPath==path&&old.SHA256==sha&&old.SizeBytes==size&&old.SourceGeneration==generation&&old.ManifestSHA256==manifestSHA&&old.KeyID==j.KeyID&&old.Label==saved.Label&&saved.Phase=="succeeded"{return nil};return ErrJournalConflict};if !errors.Is(e,sql.ErrNoRows){return e};if saved.Phase!="verifying"{return ErrJournalConflict}
 _,e=tx.ExecContext(ctx,`INSERT INTO backups(id,created_at,format_version,encrypted_path,sha256,size_bytes,source_generation,status) VALUES(?,?,1,?,?,?,?,'created')`,j.BackupID,maintenanceStamp(),path,sha,size,generation);if e!=nil{return e}
 _,e=tx.ExecContext(ctx,`INSERT INTO backup_details(backup_id,operation_id,owner_run,label,key_id,manifest_sha256) VALUES(?,?,?,?,?,?)`,j.BackupID,j.OperationID,j.OwnerRun,saved.Label,j.KeyID,manifestSHA);if e!=nil{return e};_,e=tx.ExecContext(ctx,`UPDATE operations SET status='succeeded',finished_at=? WHERE id=? AND status='verifying'`,maintenanceStamp(),j.OperationID);if e!=nil{return e};return tx.Commit()
}
func(r *Registry)StartMaintenanceVerify(ctx context.Context,j MaintenanceJob)error{tx,e:=r.db.BeginTx(ctx,nil);if e!=nil{return e};defer tx.Rollback();s,e:=scanMaintenance(tx.QueryRowContext(ctx,`SELECT `+maintenanceColumns+` FROM operations o JOIN maintenance_intents m ON m.operation_id=o.id WHERE o.id=?`,j.OperationID));if e!=nil{return e};if s.Action!="backup.verify"||s.Phase!="running"||s.BackupID!=j.BackupID||s.KeyID!=j.KeyID||s.ExpectedHash!=j.ExpectedHash{return ErrJournalConflict};var ok bool;e=tx.QueryRowContext(ctx,`SELECT b.sha256=? AND d.key_id=? AND b.status NOT IN ('deleted','expired') FROM backups b JOIN backup_details d ON d.backup_id=b.id WHERE b.id=?`,s.ExpectedHash,s.KeyID,s.BackupID).Scan(&ok);if e!=nil{return e};if !ok{return ErrJournalConflict};_,e=tx.ExecContext(ctx,`UPDATE operations SET status='verifying' WHERE id=? AND status='running'`,s.OperationID);if e!=nil{return e};return tx.Commit()}
func(r *Registry)CompleteBackupVerify(ctx context.Context,actor,operationID string,report VerificationReport)error{
 if !uuidMaintenance.MatchString(report.BackupID)||!revisionMaintenance.MatchString(report.VerifierRevision)||!hashPattern.MatchString(report.CipherSHA256)||!keyMaintenance.MatchString(report.KeyID){return ErrInvalidMetadata};c:=report.Checks;full:=c.EnvelopeAuthenticated&&c.Manifest&&c.DatabaseIntegrity&&c.SchemaChecksums&&c.VaultPairing&&c.ExternalReferences
 if report.Outcome!="verified"&&report.Outcome!="invalid"&&report.Outcome!="unavailable"||report.Outcome=="verified"&&!full{return ErrInvalidMetadata}
 evidence,_:=json.Marshal(struct{Source string; Report VerificationReport}{"OWNER_ATTESTATION",report})
 tx,e:=r.db.BeginTx(ctx,nil);if e!=nil{return e};defer tx.Rollback();s,e:=scanMaintenance(tx.QueryRowContext(ctx,`SELECT `+maintenanceColumns+` FROM operations o JOIN maintenance_intents m ON m.operation_id=o.id WHERE o.id=?`,operationID));if e!=nil{return e};if s.Actor!=actor||s.Action!="backup.verify"||s.BackupID!=report.BackupID||s.ExpectedHash!=report.CipherSHA256||s.KeyID!=report.KeyID{return ErrJournalConflict}
 var sha,k,oldEvidence,oldOperation,status string;e=tx.QueryRowContext(ctx,`SELECT b.sha256,d.key_id,COALESCE(d.verification_evidence,''),COALESCE(d.verification_operation,''),b.status FROM backups b JOIN backup_details d ON d.backup_id=b.id WHERE b.id=?`,s.BackupID).Scan(&sha,&k,&oldEvidence,&oldOperation,&status);if e!=nil{return e};if status=="deleted"||status=="expired"||sha!=report.CipherSHA256||k!=report.KeyID{return ErrJournalConflict};var attemptEvidence sql.NullString;e=tx.QueryRowContext(ctx,`SELECT evidence_json FROM maintenance_intents WHERE operation_id=?`,operationID).Scan(&attemptEvidence);if e!=nil{return e};if s.Phase=="succeeded"&&attemptEvidence.Valid&&attemptEvidence.String==string(evidence){return nil};if s.Phase!="verifying"{return ErrJournalConflict}
 stamp:=maintenanceStamp();if report.Outcome=="verified"{_,e=tx.ExecContext(ctx,`UPDATE backups SET status='verified',verified_at=? WHERE id=?`,stamp,s.BackupID)}else if report.Outcome=="invalid"{_,e=tx.ExecContext(ctx,`UPDATE backups SET status='unusable',verified_at=NULL WHERE id=?`,s.BackupID)};if e!=nil{return e}
 restore:="";if p:=report.RestoreProof;p!=nil&&p.OwnerLogin&&p.OldProfileFresh&&p.RevokedRejected&&p.CaddyValidated&&p.RollbackPassed&&report.Outcome=="verified"{restore=stamp}
 if report.Outcome=="verified" { _,e=tx.ExecContext(ctx,`UPDATE backup_details SET verification_operation=?,verification_evidence=?,restore_tested_at=COALESCE(NULLIF(?,''),restore_tested_at) WHERE backup_id=?`,operationID,string(evidence),restore,s.BackupID);if e!=nil{return e};if restore!=""{_,e=tx.ExecContext(ctx,`UPDATE backup_details SET restore_operation=? WHERE backup_id=?`,operationID,s.BackupID);if e!=nil{return e}} }; _,e=tx.ExecContext(ctx,`UPDATE maintenance_intents SET evidence_json=? WHERE operation_id=? AND evidence_json IS NULL`,string(evidence),operationID);if e!=nil{return e};_,e=tx.ExecContext(ctx,`UPDATE operations SET status='succeeded',finished_at=? WHERE id=? AND status='verifying'`,stamp,operationID);if e!=nil{return e};return tx.Commit()
}
func(r *Registry)CancelMaintenance(ctx context.Context,actor,operationID string)error{tx,e:=r.db.BeginTx(ctx,nil);if e!=nil{return e};defer tx.Rollback();j,e:=scanMaintenance(tx.QueryRowContext(ctx,`SELECT `+maintenanceColumns+` FROM operations o JOIN maintenance_intents m ON m.operation_id=o.id WHERE o.id=?`,operationID));if e!=nil{return e};if j.Actor!=actor{return ErrJournalConflict};if j.Phase=="cancelled"{return nil};if j.Phase!="queued"&&!(j.Action=="backup.verify"&&j.Phase=="verifying"){return ErrJournalConflict};stamp:=maintenanceStamp();_,e=tx.ExecContext(ctx,`INSERT INTO operation_steps(operation_id,step_no,step_name,state,started_at,finished_at) SELECT ?,COALESCE(MAX(step_no),0)+1,'cleanup','succeeded',?,? FROM operation_steps WHERE operation_id=?`,operationID,stamp,stamp,operationID);if e!=nil{return e};_,e=tx.ExecContext(ctx,`UPDATE operations SET status='cancelled',finished_at=? WHERE id=?`,stamp,operationID);if e!=nil{return e};return tx.Commit()}
func(r *Registry)PrunePlan(ctx context.Context,keep int)(MaintenancePrunePlan,error){
 p:=MaintenancePrunePlan{IDs:[]string{}};if keep==0{keep=3};if keep<2||keep>1000{return p,ErrInvalidMetadata}
 rows,e:=r.db.QueryContext(ctx,`SELECT id,sha256,status,source_generation,COALESCE(verified_at,'') FROM backups ORDER BY created_at DESC,id DESC`);if e!=nil{return p,e};defer rows.Close()
 type state struct{ID,SHA,Status string;Generation int64;Verified string};all:=[]state{}
 for rows.Next(){var s state;if e=rows.Scan(&s.ID,&s.SHA,&s.Status,&s.Generation,&s.Verified);e!=nil{return p,e};all=append(all,s)};if e=rows.Err();e!=nil{return p,e}
 raw,_:=json.Marshal(all);p.ExpectedStateHash=digest(raw)
 generations:=map[int64]bool{};retained:=map[string]bool{}
 for _,s:=range all{if s.Status=="verified"&&s.Verified!=""&&!generations[s.Generation]&&len(generations)<2{generations[s.Generation]=true;retained[s.ID]=true}}
 if len(generations)<2{return p,nil}
 for _,s:=range all{if s.Status=="verified"&&s.Verified!=""&&!retained[s.ID]{if len(retained)<keep{retained[s.ID]=true}else{p.IDs=append(p.IDs,s.ID)}}};return p,nil
}