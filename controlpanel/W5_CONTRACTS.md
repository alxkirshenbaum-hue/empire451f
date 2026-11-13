# W5 contract mapping (development copy)

Baseline: 317b1d5 (G3 production / G4 evidence remain unchanged).
This document is a design map, not G5 acceptance.

| Existing mechanism | Reuse / extension |
|---|---|
| QueueOwnedCreate / stageCreate | Keep verified-cutover admission, transactional idempotency, capacity and exact-login uniqueness. Add operation-specific request hashes, expected_version, reason and delete confirmation; protect master_user and all protected records before staging. Conflicting queued/running/verifying/reconcile work must block the same target. |
| ApplyCreate | Generalize dispatch under the existing global installation lock. No SQL transaction while applying/probing. Keep staged desired state distinct from effective state. |
| RecoverCreate / CompleteVerifiedCreate | Reuse inspect-first recovery and short CAS commit. Extend per-operation expected old/new status and credential references. A lost response and timeout follow the same inspection path; never generate another secret or blindly reload. |
| Prepared / UnixRuntime | Shared PrepareAuth/PatchAuth now handle insertion, exact-secret replacement and removal. Existing Apply, Verify, Rollback and ReadPrepared remain canonical. Domain protection belongs to admission, not raw JSON patching. |
| owned_auth.py / panel-auth-pending.json | Extend existing prepare and finish checks, currently create-specific; keep exact before/candidate, owner/run/generation, both file preimages and durable journal. No second journal or daemon. |
| createCaddyWorker / probe | Extend existing dispatcher and stdin probe contract, preserving sandbox and fixed policy. Never auto-restart. Reuse ApplyNotice before queue submission. |

## Operation-specific postconditions

- Disable: active -> disabled only after fresh old-credential denial and independent control success. Retain encrypted credential for enable. Existing tunnels may continue.
- Enable: disabled -> active using the same retained credential; fresh positive, wrong-password denial and control success. An already confirmed target state returns current state without reload.
- Rotate: stage encrypted v+1 once, preserve v for rollback; new PASS, old FAIL, independent control PASS before atomically switching active reference. Do not publish a profile before success.
- Delete: regular only, explicit confirmation; fresh denial and control success before tombstone. Keep login reserved and retain encrypted credentials according to retention policy; no hard-delete.
- All: inspect SQLite, both file generations/preimages, full live Caddy and fresh connections. Proven candidate completes; unknown state becomes reconcile_required and blocks conflicting writes pending SSH recovery. Do not infer success from file hashes alone.

## G5 parameter matrix to implement

One runner must parameterize create/disable/enable/rotate/delete and the following
14 named points, matching specification section 6.1 steps 1–14. These are required
cases, **not executed crash evidence**:

| Step | Failure point |
|---|---|
| 1 | after_global_lock |
| 2 | after_observed_preflight |
| 3 | after_running_commit |
| 4 | after_snapshot |
| 5 | after_desired_stage |
| 6 | after_candidate_render |
| 7 | after_validate |
| 8 | after_prepared_fsync |
| 9 | after_apply |
| 10 | after_fresh_verify |
| 11 | after_verified_db_commit |
| 12 | after_rollback_verify |
| 13 | after_reconcile_required |
| 14 | after_staging_cleanup |

The rollback/reconcile branches require injected primary failures before their
named crash points. Restart performs read-only inspection first. Each case must
prove old/new state or blocked reconcile, including file/live/SQLite agreement,
secret reuse and operation-specific fresh probes. Protection, exact-case,
100 regular + master capacity, tombstone reuse, CAS, duplicate requests and
concurrent disable/rotate remain separate assertions. Adapter memory-runtime
tests prove patch/recovery mechanics only, not real auth or SIGKILL behavior.
