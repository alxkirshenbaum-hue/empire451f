# G5 acceptance — 2026-11-14 (isolated copy)

Code: 64718cf. G5 PASS on copy; production remains accepted G3 code.
No production CRUD/deploy/restart, WG/firewall/routes or reserved VDS changes.

## Evidence

| Check | Revision / environment | Observation |
|---|---|---|
| Full Go suite, both VPN_TEST_CADDY_ADAPTER=1 and VPN_TEST_NAIVE_PROBE=1 | 64718cf, /opt/empire-vpn/cache/w5-pinned-64718cf, separate systemd PrivateNetwork/PrivateTmp/ProtectSystem=strict | PASS, including 70 SIGKILL and explicit SSH recovery cases |
| Dependencies | 6d31aca, unchanged go.mod/go.sum through 64718cf, existing file proxy, GOSUMDB=off/GOTOOLCHAIN=local/GOFLAGS=-p=1 -mod=readonly | go mod verify PASS; repository/pinned SHA256 go.sum d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825 |
| Python consumers | 6d31aca pinned, separate PrivateNetwork/PrivateTmp/ProtectSystem=strict | 69 tests PASS, 4 skips; no Python changes through 64718cf |
| Every real mutation and proof | 579190c, RootDirectory5002 | Real CLI/worker/Caddy/Naive: disable/no-op/enable/rotate/delete/replay/TCP/UoT/site/TLS, owner issuance and installer return PASS |
| Explicit root SSH recovery | 6d31aca, RootDirectory5003, dedicated new root/source directory | Real SQLite abort after candidate apply; explicit rollback, same-request replay, new intent, another abort, explicit complete and completed-response replay for every mutation. Normal timer does not make this decision |
| Real shipped probes | b318738 development copy, PrivateNetwork loopback | Each disable/enable/rotate/delete positive or denial + independent control TCP/UoT/TLS/site; rotate new PASS, old FAIL |
| Effective state / metadata CAS | 64718cf | Read projections report reconcile_required while effective auth is uncertain; durable pre-state retained. Conflicting metadata changes blocked |

RootDirectory5003 unit journal: successful exit after 7m28.264s; socket UID982/mode0200/parent0700.
Its output transport remained open, so completion was independently confirmed from
unit journal and read-only synthetic SQLite aggregates, not guessed from silence:
integrity ok; rotate/delete/enable each one rolled_back + one succeeded;
disable two rolled_back + two succeeded (including no-op); create/stage/cutover
succeeded; users active2/deleted1; migration rolled_back/installer_returned.
The unchanged real worker/probe/rehearsal evidence at 6d31aca is reused through
64718cf: the only later changes are users.go metadata projection/CAS and its test;
the final full Go suite ran on 64718cf.

G0b/G3/G4 reuse: [G4 matrix](G4_ACCEPTANCE_2026-11-13.md) and
[G3 production acceptance](G3_ACCEPTANCE_2026-11-13.md), with their own pinned
revisions/environments/observations. G5 does not repeat deployment or canary creation.

## Parameterized crash evidence

One runner: TestG5NamedCrashMatrix; create/disable/enable/rotate/delete ×14 points.
Every child is actually SIGKILLed and its signal checked. Restart either proves
the exact staged candidate/files/SQLite outcome or blocks reconciliation.
This is a file-backed Caddy Runtime with synthetic probe callbacks, not 70
Naive end-to-end crash runs. Real UnixRuntime/Prepared evidence is reused from
G4 and the separate real per-operation/recovery rehearsal above.

| Step | Named point | Controlled restart result |
|---|---|---|
| 1 | after_global_lock | Queued intent completes normally |
| 2 | after_observed_preflight | Queued intent completes normally |
| 3 | after_running_commit | Reconcile blocks incomplete preparation |
| 4 | after_snapshot | Reconcile blocks incomplete preparation |
| 5 | after_desired_stage | Same durable queued intent/secret retained; reconcile blocks |
| 6 | after_candidate_render | Reconcile blocks incomplete preparation |
| 7 | after_validate | Reconcile blocks incomplete preparation |
| 8 | after_prepared_fsync | Old live config is not confused with applied candidate; reconcile |
| 9 | after_apply | Exact candidate verified and committed, no repeat load |
| 10 | after_fresh_verify | Candidate reverified and committed, no repeat load |
| 11 | after_verified_db_commit | Succeeded commit retained; bound cleanup, no repeat load |
| 12 | after_rollback_verify | Explicit common SSH rollback interrupted, old live retained; reconcile then explicit rollback completes |
| 13 | after_reconcile_required | Queue blocked; explicit SSH complete requires live/files/fresh proof |
| 14 | after_staging_cleanup | Succeeded result and idle replay |

Desired records/secrets are staged transactionally at queue admission; point5
observes the original durable intent after snapshot and before rendering.
Rollback/reconcile points use injected primary failures or the explicit protected
recovery branch; they are not fictitious steps on the success path.

Separate assertions cover protected master, exact-case identity, capacity100+1,
tombstone login reservation, CAS, one secret across reopen/replay, concurrent
disable/rotate serialization, drift refusal, no-op without load, lost-load-response
inspection, current-reference switch and old encrypted credential retention.
Credentials remain private; no profile/configuration secrets are in this report.

## Limits / next step

Revocation forbids fresh connections; existing CONNECT termination is not promised.
No automatic restart fallback. Missing/damaged prepared material needs manual SSH
inspection; recovery refuses to guess. No production rollout is included.
W6 must implement the [base/optional routing policy](PROFILE_ROUTING_POLICY.md);
both phone versions and W7 interfaces remain open. E1/G6–G9 are not accepted by G5.
