# W8 snapshot inspection — verified increment, 2026-11-14

Pinnedc4bf7bb includes WIPfcea3d4 + error contractb50cd99 + independent tests
9b47886/ba381b8/fa803e8, formattingc4bf7bb. NewRegistry.InspectSnapshot and
shared vault/migration refactor first compiled/tested in localVPNControl-Lab.

PASS: targetedgo test -count=1 ./internal/storage -run Snapshot -v (8namedtests,
subcases for corruption/5unfinished statuses/emptyID;1.422s). PRAGMAquery_only
positive proves data writes not needed; wrongkey/corruptciphertext/checksum/
missingcurrent/protectedcorruption/missingmaster reject; deletedrevokedcurrent
accepted; ownID only excludes validated runningbackup.create, emptyIDexcludesnone.
Result JSON is exactly4aggregatefields, no usernames/credentials/generation.

PASS: affected consumers go test -count=1 ./... samepinc4bf7bb, systemd-run
PrivateNetwork; Caddy/Naive/SFA1.14.4+alpha13/DNS flags all enabled. API,CLI,auth,
caddy,storage,vault packagesPASS; no-tests status/migrations packages reported.
Existing offlineproxy,readonlygo.mod/go.sum flags/toolchain reused. No Python
changes/newdependencies, no repeatPython suite or unchanged infrastructure research.
Previous lab qualification774c07a remains applicable to unchanged paths.

Independent lead_coder actualsecurityreview approved errorclassification, readtxn
cleanup, sharedvault refactor and ownIDguard. Coder independently fixed fixtures;
orchestrator composed and executed tests. No failedfix-validation attempts,
architect0. RuntimeOpen migration path tested by affected packages.

Limitations: this validates one readview of an already-open canonical registry,
not a backup. No onlinebackup/filesnapshot/SQLfilegenerationbinding or endpoint.
Readview ends on return; must inspect actually capturedDB, not assume latercopy
matches preflight. Migrationrecord checksums are checked, not a full authenticated
DDL-object identity of untrusted archives. Caller must holdinstallationwriter and
checkprepared/fileintents. No newverifiedstatus/G8/usable restore/resource claim.

Roles confirmed from tools: explorerLunaHigh(readonly),coderSolLow,
lead_coderSolMedium,architectAstraMedium. Onlycoder/lead_coder instantiated for
useful tasks, no nestedchains; mainmodel settings not observable/modified.
Follow new coder2failedattempts→lead_coder, lead_coder3→architect; preserve prior
owner stopbudget, no resetting counts acrossroles. No productionchanges/deploy.

Next: actualonlinebackup/stagedDB validation/filebinding, reuse commonwriter/
existing operations/vault/envelope. W8/1 stillPARTIAL, W8 0/4fullyclosed;
W6 3/4/W7 3/4/W9 0/4/W9.1 0/6; sharedE1requiresG9.1.
