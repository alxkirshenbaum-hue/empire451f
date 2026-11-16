# Whole U criteria accepted locally — 16 November 2026

U: **W9U 3/5** (02,04,05), **W10U 1/4** (03). W8U 0/4, W13U 0/4,
W14U 0/4 unchanged. E: W8E 3/8 reused, no new E closure.
G6/G7/G8/G9/G9.1 and owner fresh-install F3 remain open.

## Pinned revisions and scope

- Runtime `5374923e2e9f27058b95f35c0e964d11a6912fab`, existing VPNControl-Lab,
  project `/opt/vpn-control/src-u-5374923-916021`, root run916021.
- Owner acceptance controller `41d05d1d086c5cd22bd9aff41bc6ff78ac3c0356`,
  `/opt/vpn-control/controller-owner-41d05d1-916023`.
- UI fixture private-parent correction `e45cb7f5dc0cfa10548500f6dc3b45138157b1dd`;
  applied only mode0700 to the owned live fixture, preserving adapter policy.
- Reused full runtime/fault matrix `2ca59b248268375a702b5190f01eb01827180d8e`,
  root916001. Its storage/auth-core/vpnctl/migration code is unchanged in5374923.

These are synthetic local component acceptances. Published rc1 still contains
runtime0c05a61; no tag, release bundle, VPS, SSH/firewall or production service
was modified. F3 remains the owner's future manual fresh installation.

## W9U02 — U_PASS

The final owner CLI used its private session to call the real owner API. The
existing canonical worker applied create, rename, disable, enable and delete.

- Exact login case preserved; create replay returned the original receipt;
  stale rename CAS and protected-master mutations refused.
- Three actual private mode0600 profiles (base1144, baseAlpha13, optionalAlpha13),
  same credential across variants; no overwrite and incompatible option refusal.
- Fresh TCP and UoT worked for issued profile. After disable/delete both were
  refused and a new profile could not be downloaded (HTTP404 / CLI exit2).
- The independent old control profile passed fresh TCP/UoT before/after changes;
  its original file remained byte-identical. `master_user` stayed protected.
- Captured CLI output was checked against session and VPN secrets in memory;
  those values are absent from reports.

Local probe copies adapt only synthetic address/port/test CA to the loopback
fixture; original profile bytes and credentials are preserved. This does not
claim a phone test or unchanged production endpoint acceptance.

The earlier916001 run also completed real revoke/no-op/enable/rotate/delete,
injected finish failures, explicit rollback/complete/replay, old/control TCP-UoT
and working-layout installer return. It finished inactive/MainPID0/success.
This supporting proof does not independently close W9U04 restart acceptance.

## W10U03 — U_PASS

Actual owner API → CLI → browser JavaScript displayed ingress observations:
CPU interval%, memory, load, filesystem available bytes, DB/WAL/SHM allocation
and RX/TX namespace counters. Values were compared with real `/proc` and statfs;
counter readings were bracketed by independent before/after OS reads.
Owner denial401 and no-store were checked. Sources and timestamps were visible.

The browser showed all five cached observations becoming stale after real TTL
elapsed, then fresh values after **Refresh local resources**. Missing backup
records showed **Not recorded**. A clearly synthetic stored-metadata fixture
tested created/unverified and saved verified timestamps, including SQLite UTC
and RFC3339→Moscow conversion. This is a timestamp reader/display test, not a
new encrypted artifact, verification or restore PASS. Existing producer proofs
in [W8_UE_EVIDENCE.md](W8_UE_EVIDENCE.md) remain reused at their boundaries.

[Structured numeric/boolean receipt](reports/W10U03_5374923_916021.json).
The local TLS frontend separately passed trustedCA/exactSNI/login/no-store,
unauthorised API/admin denial, UID981/CapEff0 and private socket boundaries.
The browser used an independently reviewed read-only synthetic localhost view;
browser TLS/login/CSRF are not claimed from that adapter. Windows→WSL localhost
forwarding was experimentally observed; no route/portproxy/trust-store changes.

History, peaks, total panel footprint, per-user traffic and live exit health are
outside this U03. W10U01/02/04 are still open.

## W9U04 — U_PASS, canonical-derived service restart and config rollback

Final controller `70c980c5402556cadee7093a16884bd939315d5f`, fixture
`37d97b52df8cef3df70be6d5cf46e7d89fd24e9a`, new root916043 under
`/opt/vpn-control/src-w9u04-37d97b5-916043`; unchanged5374923 binaries.
[Typed receipt](reports/W9U04_5374923_916043.json). Main independently verified
public template SHA against exact Git-archive LF bytes, not Windows CRLF copies.

- Canonical API/frontend Service properties retained, with explicit lab-only
  RootDirectory/network namespace, unique unit/runtime names, executable/socket,
  credential and environment-file path substitutions. No host manager socket or
  admin socket was exposed. Production unit files were not changed.
- Real `systemctl restart` of the same units produced new PIDs and sockets;
  former canonical PIDs ended. Exact owner/session identity, user/credential/
  profile bindings, statuses/master protection, vault and original profile bytes
  were preserved. Only legitimate session last_seen changes were excluded.
- Trusted CA/SNI and owner response through the real TLS frontend passed.
  The same UID/sandbox probe confirmed proc/registry/vault denial and admin
  ENOENT/EACCES. All Cache-Control directives had to be no-store; duplicate
  no-store fields were accepted without permitting public/max-age directives.
- A controlled invalid PROFILE_DOMAIN produced nonzero ExecMainStatus and
  Result=exit-code. Canonical autorestart was retained, then the owned API unit
  was explicitly stopped. While API was unavailable, fresh master/old-control
  TCP/UoT continued working.
- Exact previous environment bytes were restored at the same path; the same
  units recovered, with owner/TLS/state and fresh TCP/UoT passing again. The
  frontend was restarted to refresh the lab RootDirectory's directory bind.

Whole controller exited0; 11 policy mocks PASS0.048s. Both canonical units and
parent fixture ended successfully; Main confirmed their completed journals,
removed runtime directories, no owned active units and no owned keeper.
Private credential/profile hashes stayed in memory; receipt contains booleans
and public canonical-template hashes only.

Three distinct test-adaptation corrections preceded the final pass: device/inode
root comparison across mount namespaces; optional denial of an already absent
admin path in private /run; comma-list handling of duplicate no-store headers.
Each was independently reviewed; no product sandbox or restart policy was
weakened. Failed roots916041/42 remain preserved, not reinitialised.

This proves service restart and configuration rollback. It does not prove boot
ordering/reboot, cross-version/schema downgrade, package rollout or full W8 DR.

## W9U05 — U_PASS, targeted regression and instructions

Pinned5374923, offline Go, separate PrivateNetwork units:

| Check | Final result |
|---|---|
| Owner API downloads/maintenance + observations | PASS 1.312s |
| Full internal/auth, including password/CAS/rollback/session/identity cases | PASS 6.447s |
| AuthPasswd/AuthWhoami/OwnerCLI private download/resources targets | PASS 0.033s |
| Mixed UTC/RFC3339 inventory ordering | PASS 0.063s |
| Browser adapter policy/transport mocks, source0bc42c9 | 8 PASS 0.049s |
| Actual owner CRUD/profile/control and actual metrics browser path | PASS as above |

go mod verify PASS; go.sum before/after:
`d21703d26da01b776d242a173790ac72e660d96a0347678923243d0f3ba8c825`.
[Owner instructions](OWNER_GUIDE_U.md) cover the accepted paths, private CLI,
queued/completed distinction, revoke/delete effects, resource scope/staleness,
stored evidence and local reproduction.

This closes the named targeted-regression/instruction criterion for this local
candidate. It is not a full exact-engine Go suite, capacity/soak, phone matrix,
production rollout, portable migration or parent G9 acceptance.

## Corrections and lifecycle

No product protection was relaxed. Four distinct acceptance issues were fixed:
numeric network `errors` collided with a generic leak substring assertion;
the synthetic session parent needed0700; refused CONNECT can produce EOF;
HTTP404 profile refusal maps to CLI exit2. Each correction retained the intended
negative guard. Final targets passed; no unresolved four-attempt failure.

Both runtime units ended inactive/MainPID0/Resultsuccess. Browser view expired
cleanly, its localhost listener was confirmed closed, owned keeper exited, and
no matching runtime/TLS/regression units remained running. Old runs/artifacts
were preserved. Raw runtime logs remain in the lab; Git contains only explicit
structured evidence, not raw diagnostic streams.

## Still open / next choice

W9U01 phone/TLS/nonadmin/external observations and W9U03 deferred migration plus
actual health remain open. Next evaluate W10U02's actual exit-local audit source
and existing collector/reader path; do not resume a partial W13 report merely
to produce another substep. No deployment-ready production package is claimed:
reviewed W10 changes must first be isolated from deferred WIP and packaged.
W14U01 needs concrete desired ingress parameters; a no-op/placeholder plan does
not count. Production changes and owner actions are skipped until available.
