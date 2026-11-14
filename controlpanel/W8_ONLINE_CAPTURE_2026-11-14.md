# W8 online SQLite capture — 2026-11-14

Verified increment, NOT G8 acceptance. Source62d44b3 ->integratede0eef09;
independenttests0760583 ->c065132; firstcomposedpinadd2d78;
concurrent-writertestebc33e8 ->finalpinned5b01836. Formatting-only integration
conflict in testfile resolved preserving all existing tests plus new testcase.

Registry.CaptureSnapshot creates only new private child0700/state.db0600 beneath
an existing trustedprivateimmutable parent. Uses alreadyinstalled SQLite driver
online Backup API, explicit sourceBEGIN+page_count/page_size to pin a boundedcut
including WAL,128page steps,15s context limit includingBUSY retry.32MiB perimage
conservative bound checked before/during copy. This is not totalG8 disk budget.
SQLiteBackup Finish completes before destination journal_modeDELETE,close and
sidecarrefusal. Actual capturedDB is openedmodeRO/query_only and inspected through
canonical Registry.InspectSnapshot; no Registry.Open/migrations. Hash streamed,
file/child/parent synced on Linux. Source rollback/close errors propagate; any
failure removes only own new child. Existing artifacts/sentinel neveroverwritten.
Path excluded fromJSON; no secretcontents or new verified/catalog status returned.

Independent authorlead_coder implemented one ownednew file; coder independently
wrote one ownedtestfile. Orchestrator independently reviewed Rawhandlelifetimes,
sourcepin/bounds/privatepath contract, standalonejournal mode and cleanup; requested
rollbackerror propagation before firsttest, incorporated successfully. No failed
fix-validation attempts; architect0. No nestedagents or production actions.

## Evidence

Local VPNControl-Lab, Go1.27.3/CGO/offlineproxy/readonlymoduleflags, separate
systemd PrivateNetwork units. add2d78 initialSnapshot|Capture tests PASS2.818s.
Final5b01836 full affectedstorage package PASS5.297s including:
- CommittedWAL data appears in standaloneimmutable copiedDB; correctSHA/size/
  aggregateinspection and permissions; different captures retain prior bytes.
- Cancelledcontext, unfinishedoperation, wrongownkind reject+cleanup; ownrunning
  backup operation allowed explicitly. Public/symlinkparent rejected.
- Oversize32MiB+ fixture fails without acceptedartifact or deleting sentinel.
- Separate external SQLite WALwriter updatesbothusers atomically during20MiB
  capture. Writer progress observed and capturedimmutableDB has consistent labels;
  cancellation/join bounded. This is not a globalDBgeneration feature.
- Existing inspector/schema/vault/mutation/crypto/recovery tests in storage pass.

No newcapturetest skipped. Package reported subprocess-only childguard skip and
3exactSFAchecker subcase skips (env not set in this storage-onlyrun). These are
NOT new exact-engine evidence. Prior full consumer suitec4bf7bb has all Caddy/
Naive/exactSFA/DNS flagsPASS; those codepaths unchanged by newcapture files.
No repeat fullGo/Python/RootDirectory scenarios: no existingcommoncode/dependency
or unit changes in this increment. Full pinned gate suite still required forG8.

API primary reference reviewed for newdriver integration:
https://www.sqlite.org/c3ref/backup_finish.html
Pagecounts update after Step; Finish exactlyonce; destination unused between
Backupinit/Finish. No external commands copied from web or production scripts run.

## Explicit limits / next step

Protected plaintext SQLite staging only: not encrypteduserbackup, noBKP endpoints/
queue/catalog/prune/restore-plan, no generation/filebinding or backupverification.
Caller must hold existing installationwriter and check file/preparedintents;
parent path must remain immutable. Not a defense against hostile root replacing
paths. Qualified onLinuxCGO; WindowsACL/privatebackend proof not claimed.
Hard32MiB bound may need revisiting under measured load and existingenvelope
streaming work; never silentlytruncate. No ENOSPC/midcopycancellation/powerloss
acceptance or complete resourcepeak evidence claimed by these cases.
Captured ownbackup operation remains at capturedrunningstatus; eventual restore
must explicitly handle authenticated ownID in existingjournal/recovery contract,
not silently reactivate queued work. Not currently restorable product package.

NEXT: bind capturedDB and managedfile hashes/generation/owner-run under existing
writer; then existing envelope encryption+operationmetadata. Actual backuprestore,
masterkeyrotation, retention and disk/RAM gates stillOPEN. W8 0/4 fullyclosed,
W6/W7 3/4, W9 0/4, W9.1 0/6, E1 6/11. No production access/change this increment.
