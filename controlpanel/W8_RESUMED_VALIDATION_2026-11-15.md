# W8 resumed local validation — 2026-11-15

Scope: user authorized local development through W9.1; no production access or changes, no push. BACKLOG is excluded. Gates G6/G7/G8/G9/G9.1 remain open; E1 6/11, W8 0/4 fully closed.

## Actual evidence

| Pinned source | Environment / test | Result |
|---|---|---|
| 9c197d7 | VPNControl-Lab, PrivateNetwork; actual owner maintenance API | PASS 0.550s |
| 4dd8956 | PrivateNetwork unit w8-rotation-4dd8956-20261115; five named vault rotation tests | PASS storage 0.513s |
| 4dd8956 | Offline encrypted roundtrip, parent ownership, actual maintenance worker crypto | PASS CLI 4.171s |
| 4dd8956 | Owner maintenance API | PASS 0.460s |
| cdb3d82 + formatting ebd28cd | PrivateNetwork; ManagedArchive targets including real ACL principal read/write probe | PASS 3.417s |
| 6a525bc | PrivateNetwork unit w8-restore-prep-6a525bc; PrepareRestoreCopy eight scenarios | PASS storage 0.932s |
| 6a525bc | Integrated ManagedArchive and Offline targets | PASS CLI 3.858s |

Offline module verification passed; go.sum SHA256 remained d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825. Immutable run/source directories retained. Units completed, runner released between packages.

The initial b1e8a67 test run failed due to fixture defects: API compared unstable envelope request/time and decoded data incorrectly; worker auth was invalid. Later worker rootFile rejection exposed archive checkout helper permissions; fixture now installs a private root-owned0600 helper, without weakening product policy. These are not successful product acceptance runs.

## Boundaries

Rotation now checks versions1→2→3, historical/revoked empty-ID credentials, wrong DB/key pairs, same key material, overflow, cancellation, partial-update transaction failure and unchanged source bytes/inode. This is a NEW offline database candidate only; no DB/key activation, pair rollback or postcommit process-crash acceptance is claimed.

Archive supports bounded user attributes and POSIX access ACL with strict validation. PAX remains refused. Verified staging stays0600 without attributes. Applying attributes to a NEW copy requires trusted destination UID/GID and independently approved exact ACL digest; an archive cannot approve its own principals. Inherited default ACL parents are refused. Actual UID65534 read passed and write was denied. Integration6f89bfb also applies shared trusted-parent checks.

Offline CLI reuses existing GCM decrypt and canonical archive/registry verifier. Output is artifact_check_passed with usable_restore=not_run; it cannot promote backup status. New --prepare-parent wiring b559d48 is awaiting its encrypted integration test. Storage preparation creates only a NEW child, validates exact backup-create operation/intent/owner/target, removes sessions and records RESTORED_INTERRUPTED plus audit in one transaction, then repeats canonical checks. Stronger session/history/exact-binding tests after6a525bc are pending.

## Independent review and current queue

ASTRA W8-SEC-002 reviewed rotation, ACL policy/application and restore-copy implementation. Reported code findings were addressed; authenticated immutable source/ancestor custody and independent ACL approval remain caller contracts. Final acceptance needs the actual encrypted prepare and restored runtime. No unresolved four-fix failure; no debugging escalations.

Lead: integration/offline CLI; SOL-A: ACL implementation/tests3/3 completed; SOL-B: API/worker tests completed, restore preparation implementation target passed, strengthening exact-binding/encrypted CLI coverage; SOL-C: rotation target completed, now implementing existing RootDirectory harness backup/restore drill. No nested agents.

Next: encrypted worker→offline preparation target, then restored stack owner login/old active profile/revoked negative/Caddy/rollback. Restore-plan/prune/audit, complete identity inventory and aggregate disk/RAM, pinned required full suite still precede G8. W9/W9.1 follow W8; phone-specific G6/G7 evidence is not inferred from the lab.
