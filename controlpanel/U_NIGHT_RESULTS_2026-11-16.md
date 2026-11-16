# U-first: local overnight work, 16 November 2026

**Subsequent whole-criterion acceptance:** W9U02+05 and W10U03 U_PASS.
See [current acceptance](U_ACCEPTANCE_2026-11-16.md); the0/5 and0/4 counters
below describe the earlier substep-only checkpoint.

Owner authorised choosing the smallest useful remaining items in W8U/W9U,
earlier U omissions, W10U/W13U/W14U, then continuing without confirmations.
Actions requiring the owner's phone or server changes are postponed. Production,
reserve, client credentials and published `v0.4.0-rc1` remain unchanged.
Portable export/import and its harness remain deferred.

## Progress and selection

U: W8U 0/4; W9U 0/5; W10U 0/4; W13U 0/4; W14U 0/4 fully accepted.
E: W8E 3/8 E_PASS_REUSED; no new E closure. Parent gates unchanged.
Broad counters require end-to-end acceptance, not just implementation.

| Order | User value | Implementation / evidence | Remaining boundary |
|---|---|---|---|
| 1 · W9U02 / PROF-03 | Recognise profile by exact login and client | `70626a2`: safe `vpn-Test-User-sfa-1.14.4.json`; unsafe legacy login uses UUID; owner download/filename PASS 0.540s | Actual phone UX pending; no password rotation |
| 2 · W10U03–04 / MET-01,04 / SYS-03 slice | Actual ingress RAM, load average and registry filesystem free bytes | `daa33d0`, `fdd0c1d`: owner API/UI, `vpnctl system resources --json`; API PASS 1.021s; final API PASS 0.354s / CLI PASS 0.010s | OS memory is not panel cgroup RAM; load is not CPU percent; DB/WAL/SHM is not whole-panel footprint; no exit producer/history/peaks |
| 3 · W9U omission / AUTH-04 | Change independent owner password | `4d40278`, `8a25436`, `216c721`: System form and `vpnctl auth passwd`; full auth PASS 4.203s, CLI PASS 79.796s; new CLI target PASS 0.015s | Actual browser interaction and installed version not proved |
| 4 · W10U03 stored evidence | Overview shows last recorded audit activity and backup timestamps | `f70bd62`: existing bounded inventories, no new collector/API; SQLite UTC display; chronological ordering of mixed UTC/RFC3339 | Registry audit includes admin changes, not exit-local audit, live health or successful restore |
| 5 · W9U omission / AUTH-03 | Know the exact independent panel owner and session expiry | `4dce892`, `21cc4e5`, `abc0876`, header `8c0309b`: `vpnctl auth whoami`, owner API, header exact username/expiry; full final auth PASS 7.251s / CLI identity PASS 0.012s | Browser rendering/phone interaction not actually exercised |

AUTH-04 independent architect review: no blocking findings. Current password,
Origin/CSRF, bounded body, crypto gate/throttle, active-session recheck and CAS
are retained. Hash replacement, revoke-all and audit are one transaction.
Negative tests: wrong password, Origin/CSRF, weak password, audit failure rollback,
concurrent winner, revocation of both old sessions and fresh login.
VPN passwords, protected master_user and vault key are unchanged.
CLI prompts interactively; no password arguments or secret output.

## Combined targeted check

Pinned `f70bd62`, `/opt/vpn-control/src-u-inventory-f70bd62`, existing
VPNControl-Lab, unit `u-inventory-f70bd62`, PrivateNetwork/offline Go.

```text
go mod verify                                      PASS
go test ./internal/storage -run '^TestInventoryChronologicalUTC$' -count=1
                                                   PASS 0.070s
go test ./cmd/vpn-control -run 'TestObservation|TestProfileFilename|TestOwnerDownloadsActiveProfile|TestMaintenanceOwnerAPI' -count=1
                                                   PASS 0.964s
node --check controlpanel/internal/auth/panel.js     PASS
```

go.sum before/after:
`d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825`.
No dependency/schema changes. Full engine suite not claimed for this night
package; prior applicable proofs reused at their actual boundaries.

Final identity/header source `8c0309b`, separate pinned PrivateNetwork run:
full `go test ./internal/auth -count=1` PASS 7.251s;
`go test ./cmd/vpnctl -run TestAuthWhoami -count=1` PASS 0.012s.
Readonly identity returns exact admin ID, username, owner role and expiry only.
Missing/revoked/idle/expired sessions and disabled owner: 401 without identity.
No password or session token appears in CLI output. Final JavaScript syntax PASS.

Usage after packaging this development branch (not published rc1): existing
private `VPNCTL_SESSION_FILE` / owner login, then `vpnctl auth whoami`,
`vpnctl auth passwd`, `vpnctl system resources --json`. Browser System has the
password form; success signs out all owner sessions and requires fresh login.

## Remaining U work and morning actions

- W8U: encrypted portable path deferred. Installer Q13 JSON → registry PASS
  `8a164c9` retained; this is not portable import acceptance. No further transfer
  fixture repairs or harness runs tonight.
- W9U01 / G6/G7: actual phone/TLS, ordinary VPN user's denial and external-access
  observations need owner participation. Historical owner create → download →
  connect retained; no complete matrix claimed.
- W9U04: actual target restart/data-plane/rollback not authorised tonight.
  No server restarts, firewall or routing changes.
- W10U01–02: live egress TCP/UDP/IP and exit-local audit need actual sources.
  Local resources/registry timestamps cannot turn them green. CPU percentage,
  history, whole-panel footprint and RAM peaks remain open.
- W13U: reuse installer allowlisted `remote.plan` / `render.change_plan` and
  controller explanation. Panel deployment approve/execute not claimed.
  The panel-to-installer bridge is still software work, larger than the selected
  self-service items; its readonly plan must precede approval/execute. Current
  installer planning reads remote owned state, so a synthetic diff does not prove
  a target preview. No second writer/journal. Target execution/SSH/rollback needs
  an authorised operation; no extra staging pair created.
- W14U: reuse existing keep-egress plan/diff. Actual ingress swap, old-profile
  TCP/UoT, new SSH and safe fault outcome remain open; none performed tonight.
- W9.5U-Fresh: published rc1 remains morning candidate. F3 OPEN until owner's
  installation on owner-cleaned nodes. Follow [FRESH_OWNER_ACCEPTANCE.md](FRESH_OWNER_ACCEPTANCE.md).
  Owner confirmed current verified JSON including master_user. Recheck freshness
  before future destructive action; agent has no node-cleanup permission.

Night commits are local development, absent from published rc1 runtime
(`0c05a6174e254192939227668f9d4947904984d4`). Do not advertise them as installed
or replace the immutable published tag.

Next software package to assess is W13U readonly plan bridging through the
existing installer. It is not blocked solely by the owner's absence: contracts
and implementation still remain. Actual target execution remains deferred.

### W13U independent architecture review

The review found concrete barriers to calling the current installer from panel:
`remote.plan()` invokes `require_installer_writer` and deliberately refuses a
panel-owned installation; this guard must not simply be removed. Fresh preview
uses placeholder keys/credentials and recalculates before apply, so its current
hash is not an immutable executable DEP-03/04 plan. File actions alone do not
describe affected users, DNS or profile effects. The panel has no established
safe observation transport to both nodes.

The next bounded partial value would be a size-bounded, allowlisted, sanitized
readonly preview report exported by the existing owner-side installer and shown
as owner-provided evidence (source revision, node identities, observation time,
hashes, path actions, risks/unknowns). No raw facts/configs/secrets/commands or
private SSH keys. This requires its own implementation and negative tests; it is
not yet implemented and would not by itself close W13U01 or authorise execute.
The five smaller implemented items above were selected first for this reason.

## Agent accountability

- profile_filename (coder): handler + safe filename + target, complete `70626a2`.
- local_observations (lead_coder): source/parser/API/UI/CLI + isolated targets,
  complete `daa33d0`/`fdd0c1d`.
- owner_password (lead_coder): atomic AUTH-04/API/CLI/form, negative and transport
  tests complete; AUTH-03 readonly API/CLI, exact ID correction and final combined
  auth/identity checks complete. No failed fix/validation cycles.
- security (architect): consequential AUTH-04 contract and final code review,
  complete, no blocking findings; W13U feasibility review complete with writer,
  immutable-plan and transport barriers identified. Did not duplicate tests.
- Main: selection/integration, stored evidence UI/time-order regression,
  pinned combined target and docs. No nested agents or concurrent heavy runs.
