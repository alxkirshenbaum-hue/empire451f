# W8 continuation checkpoint — 2026-11-15

User authorized LOCAL development through W9.1; production excluded. Work interrupted by agents usage limit, not four failed corrections. Latest code HEAD8708435. This is an additional checkpoint; read original HANDOFF_W8_2026-11-15.md for environment/constraints. No push/production changes; BACKLOG untouched.

Progress unchanged: E1 6/11, W6 3/4, W7 3/4, W8 0/4 fullyclosed, W9 0/4, W9.1 0/6. All later gates open. Source backup and restored runtime are now actual partial proof; full rollback not yet PASS.

## Verified since original handoff

- Two c99e9b0 tests integrated separately; fixture errors corrected. Pinned4dd8956 actual ownerAPI PASS0.460s; crypto worker/offline roundtrip+parent checks PASS4.171s; five rotation tests PASS0.513s. modverify/go.sum unchanged.
- Rotation versions1→2→3, historical/revoked empty-ID credentials, wrong pairs/samekey/overflow/cancel/partialupdate/source bytes+inode PASS. Copy-only; activation/DB-key pair rollback and postcommit crash unclaimed.
- ACL/xattrs allowlist + actual UID65534 read/write denial roundtrip PASS3.417s; integrated archive/offline targets6a525bc PASS3.858s. Trusted independent ACL digest required for new-copy application.
- Restore preparationb0dbd99:13scenariosPASS1.584s; exact binding/session invalidation/RESTORED_INTERRUPTED/audit/history/source unchanged. Encrypted worker→offline CLI --prepare-parent03bb43f PASS2.025s.
- Readonly plan849edc8 targetPASS0.334s; owner/hash/stale/crossowner negatives. CLI fresh-manifest/writer binding remains unwired.
- Wrapper explicit trusted path+SHA policy2c5733e + testsd64e7b5/0a360f9:8casesPASS0.254s. Actual source archive includes /usr/local/bin/vpn-add-user; defaults still deny absent policy. Trusted readonly packaged executable supplies runtime, archived bytes must match.
- Source actual backup: project /opt/vpn-control/src-drill-0c05a61-20261115005710, run851541, successful unit, ciphertext+proof retained. Private RSA remains outside RootDirectory. Do NOT repeat source phase.
- Recovery controller7c6d0dd/destination851571: offlineverify/preparation + restored Caddy/API/owner login/unchanged old profile freshTCP-UoT/revoked negative PASS. Rollback source verification failed FileExistsError on existing trusted scratch. Latest8708435 fixes validated reuse of scratch; NOT yet rerun/accepted. Full report not produced.

## Exact next action

Read current pilot/run_backup_restore_rehearsal.py options. Transfer NEW immutable controller source at/after8708435; recovery-only reuse source851541 and NEW destination ID (851581 was planned, existence not checked). Host --project above --run-id851541 --resume-source --destination-id NEW; --recovery-cli if required points to separately built wrapper-policy CLI (inspect prior controller/run metadata, do not overwrite). Existing controller /opt/vpn-control/controller-04d45bd-20261115010025 is historical and lacks latest corrections. New controller must match pinned inner helper overlay; CLI source must include wrapper policy/static stage diagnostics. No private RSA inside runtime.

WSL read-only check after interruption returned0 loaded w8-*/vpn-full-worker-root-* units and no vpnctl/vpn-control/sing-box/caddy processes (grep exit1 means none). Old run directories/ciphertexts/keys retained private, not in Git. No cleanup/delete needed.

## Uncommitted WIP — NOT compiled/tested

Tracked: cmd/vpnctl/backup_worker_linux.go, worker_linux.go, internal/storage/maintenance.go.
New: cmd/vpnctl/backup_audit_linux_test.go, backup_prune_linux_test.go; internal/storage/maintenance_audit.go/test, maintenance_prune.go; pilot/w8_audit_worker.py.

SOL-B said compile-ready, but no compile/target result. Do not treat this as PASS or blindly commit with documentation. Prune/audit implementation ASTRA review was interrupted by usage limit. W8-SEC-003 DESIGN conditionally approved only: exact durable CAS plan, >=2 retained verified distinct generations rechecked per unlink authorization, trusted immutable rootfd, nofollow/inode/digest, directoryfsync before DBdeleted, honest missing_after_intent. Audit safe collection success is not security-gatePASS;22unknown/notrun retained. First inspect WIP then format/pin/compile/target crash/negative tests and independent implementation review.

Lead: offlineCLI/integration/host orchestration. SOL-A:ACL3/3+wrapper8testsPASS. SOL-B:API/worker/restoreprep/readonlyplanPASS; prune/auditWIP. SOL-C:rotationPASS/sourcebackupPASS/restoredruntimePASS; source rollback scratch latestfix unvalidated. ASTRA:W8-SEC-002 and W8-SEC-003 planned reviews; latest prune implementation review incomplete due limit. Loader issue1failedfix thenPASS; sessionCLI issue1failedfix thenPASS; scratch issue1failedfix then secondfix8708435 unvalidated. No unresolved four-fix failure, no debugging escalation.

Remaining: finish recovery-only rollback proof; complete/test/review prune+audit; readonly restore-plan CLI fresh generation; rotation activation/version/rollback handling; complete identity/secret matrix and aggregate disk/RAM; required new pinned fullGo/Python/exact-engine suite before G8. Then W9 and six W9.1 items. G6/G7 missing phone/actual matrix not inferred; Download Manager deferred. Use original HANDOFF env/toolchain/proxy/keeper/RootDirectory constraints; no reinstall/mntc/production.
