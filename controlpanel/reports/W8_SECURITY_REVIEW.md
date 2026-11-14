# W8 security coverage — SOL-B

Status: package prepared; stages 3/3 (inventory, fixture code, static review).
Targeted unittest PASS: 5 tests using app-bundled Python 3.12.14 discovered
by Lead; WindowsApps alias unusable. Independent Linux runner still pending. No Linux/runtime/security acceptance is claimed.
Base: 84c5262. Failed-fix count: 0; no failed corrective iterations.

The pure checker assesses synthetic metadata only. Its fixed finding IDs are
local test assertions, not a second audit schema, collector, daemon or SEC PASS.
Callers must never promote an empty fixture result to observed security evidence.
It does not read files, execute commands, import the collectors or print inputs.

## Existing audit / LLD coverage inventory

Existing security_audit.py is the managed-node collector to reuse through an
approved launcher. Despite its read-only docstring its firewall comparison runs
unshare/nft in an isolated namespace. controlled_audit.py performs outages.
Neither was executed. Existing historical W7 proofs are not fresh W8 evidence.

| LLD IDs | Evidence / gap | Severity / current disposition |
|---|---|---|
| SEC-01–05 | Existing SSH/listen/firewall/WG audit; approved runtime collection required | critical / unknown |
| SEC-06 | controlled outage suite, explicitly outside this fixture package | critical / not_run |
| SEC-07 | Existing namespace checks; actual UID, capabilities, foreign UID, proc-root, mounts need Lead staging | high / unknown |
| SEC-08 | Existing unit observations and historical socket ordering proof; fresh graph/restarts pending | high / unknown |
| SEC-09 | Synthetic owner/mode/link/foreign UID/proc-root/redaction negatives for all listed surfaces | critical / fixture only; ACL/runtime unknown |
| SEC-10–12 | Existing config/plugin/TLS/site checks; no current collection here | high / unknown |
| SEC-13–14 | Existing bounded UoT/egress probes; no probe here | high / not_run |
| SEC-15 | Existing health observations; complete aggregate disk and RAM measurement missing | medium / unknown |
| SEC-16 | Existing storage tests; no integrity/vault/migration collection here | critical / unknown |
| SEC-17 | Restore package requires independent review and real restore evidence | high / unknown |
| SEC-18 | Existing auth probe, not run here | high / not_run |
| SEC-19 | Synthetic retention assertion only; actual expired artifact cleanup evidence missing | medium / unknown |
| SEC-20 | Existing W7 security tests/history; fresh identity/auth/session/CSRF checks pending | high / unknown |
| SEC-21 | Synthetic off-VDS custody, sentinel pairing and usable restore kept separate | critical / unknown runtime |
| SEC-22 | Historical reboot evidence; no reboot authorized/performed here | high / not_run |

## Surface and resource boundaries

Fixture classes: auth, clients, profiles, exports, DB, WAL, vault, snapshots,
temp, backup and logs. Regular-file/single-link assertions reject symbolic and
hard-link exposure in fixtures; actual path traversal, TOCTOU and proc-root
operations need Linux tests under root/API/frontend/Caddy/relay identities.
POSIX metadata is not Windows ACL proof. Redaction boolean is not an inspection
of stdout/stderr/URL/argv/report: only fixed checker output is locally designed
not to echo input. Test includes a synthetic canary, never real credentials.

Disk and RAM are separate 500,000,000-byte gates, aggregate across both VDS and
all panel jobs. Metadata must cover WAL, versions, temp/backup peaks, retention,
open deleted files, worker/helper descendants and cgroup memory.current/peak plus
RSS/PSS; caps and fixture numbers are not measurements. These remain unknown.

Key custody must prove recipient private key off VDS, matching sentinel decrypt,
and usable restore independently. Sentinel success alone is not registry/runtime
consistency. Rotation drill/runbook and retention proof remain blocking gaps.
Known leaf expiry 25 November is historical context, not a fresh TLS check;
Lead must verify renewal mechanism and current certificate before expiry.

Minimal next actions: retain targeted unittest evidence and
stage actual denied open/listdir/proc-root/link traversal operations; reuse
existing audit under approved launcher; measure complete disk/RAM peaks; verify
key rotation and real restore. No unit/helper/migration/production changes here.
Independent SOL-A stable commit review remains pending its availability.
## Independent SOL-A review (different author)

Reviewed pinned history 4285e73 -> 4d7c1f9 -> 1de0c25, read-only.
Final targeted execution: test_w8_backup_artifacts.py, 5 tests PASS (0.747s)
using bundled Python 3.12.14. Review is separate from SOL-B initial stages 3/3.

Initial findings and disposition:
- P1 whole-archive retention: resolved in 4d7c1f9 with chunked archive/member
  hashing and descriptor retention; metadata capped at 1MiB. End-to-end M-006
  remains open because the existing envelope buffers, plus no peak measurements.
- P2 leaf check/open race: 1de0c25 uses one regular single-link FD and Linux
  O_NOFOLLOW where available with before/after identity/size/timestamps. Caller
  MUST enforce private immutable staging including parents. This is not hostile
  concurrent-writer proof or Windows nofollow proof. It does not double-hash the
  whole archive after parsing; timestamp checks are supplementary only.
- P2 ignored inventory ownership/metadata and arbitrary unlisted content:
  1de0c25 compares uid/gid/mode and digest shape, rejects nonempty xattrs and
  unlisted files except explicit state.db. Uninventoried DB stays unchecked;
  registry_consistency=not_run and pending gates correctly prohibit promotion.
- P2 GNUtar ACL/xattr/PAX compatibility: unresolved and explicitly documented.
  Conservative rejection is acceptable for a limited fixture candidate; actual
  producer round-trip is required before BKP integration or G8 acceptance.

Verdict: acceptable to merge as a limited read-only copy candidate under the
Lead integration contract, not deployable backup/restore or G8 acceptance.
No new blocking finding within that scope. State.db completeness/consistency,
private staging enforcement, hostile mutation/parent protection, true producer
compatibility, envelope/aggregate resource bounds and usable restore remain open.
Lead W8_INTEGRATION_CONTRACT.md independently reviewed: no blocking semantic
finding; evidence levels, persisted-state prohibition and production gates clear.
Failed corrective attempts attributable to this review: 0.
## Final SOL-A revision and exact collector mapping

6dde629 independently reviewed against 1de0c25: O_BINARY is appropriate for
Windows binary archives; added binary/owner/mode/xattr/unlisted/hardlink tests.
Executed final targeted suite: 8 tests PASS, no skips (0.717s). Prior limited
merge verdict unchanged; no new blocker. No claim of GNU producer compatibility.

Next package progress: 2/2 (source mapping + evidence/gap recording), static
inspection only. References below are security_audit.py at baseline 84c5262;
collector has human labels rather than implemented SEC-xx identifiers. Thus
these are coverage mappings, NOT execution results or automatic SEC PASS.

| Expected ID | Actual source coverage | Exact missing boundary |
|---|---|---|
| SEC-01 | 57–66 effective sshd config | line58 session assertion trusts launcher; no independent key-auth method evidence |
| SEC-02 | 92–95 local1081 only | no complete external listen inventory on either node; no panel exposure scan |
| SEC-03 | 50–55,75,82 rules equality;153–156 exit SSH | trusts installed reference files; equality not independent expected-policy review |
| SEC-04 | 67–72 host route;80 namespace default;97–101 DNS/outbound;157–158 forwarding/allowedIPs | no full live WG peer/endpoint/routes/NAT semantic inventory |
| SEC-05 | 75,82 reference rule match | no standalone semantic fail-closed proof independent of installed reference |
| SEC-06 | none | dynamic WG-down TCP/UDP/DNS/IPv4/IPv6 belongs approved controlled suite, not this audit |
| SEC-07 | 109–119 process ns/UID/caps/resolver;80 routes | no API/frontend/worker identities, exact allowed UID, mount secret denial, foreign UID/proc-root access test |
| SEC-08 | 120 restart policy;159–161 active/enabled/graph/journal | no restart-count trend; current checks are point-in-time |
| SEC-09 | 46–48,76,83,87–91 key/profile/ACME modes | no complete auth/vault/DB/WAL/snapshot/temp/log/SSH surface inventory, hardlink/ACL or log-secret inspection |
| SEC-10 | 74 installed hashes;84–86 Caddy tokens | no plugin presence/order-handler/safe-auth semantic checks; tokens alone not effective config |
| SEC-11 | 124–131 trusted TLS1.2/1.3 ALPN | no expiry margin or renewal method evidence; successful handshake only proves current validity |
| SEC-12 | 102–106 pinned verifier;144–146 site200/404 | verifier supplied by launcher, collector-alone cannot run; independent scenario details delegated |
| SEC-13 | 92–106 loopback config/listener plus UoT verifier | smoke delegated; no standalone evidence without pinned verifier |
| SEC-14 | 102–106 expected verifier result | expected egress delegated, no independent direct-fallback observation here |
| SEC-15 | none | system time/NTP drift, disk/volume space, OOM events and failed units absent |
| SEC-16 | none | SQLite integrity/migrations/vault unlock/secrets protection absent |
| SEC-17 | none | backup age, verified timestamp, actual restore evidence absent |
| SEC-18 | 102–106 delegated valid-client probe;147–152 invalid/anonymous concealed | explicit local Caddy valid/invalid sample auth test not implemented as independent collector check |
| SEC-19 | none | expiry/retention and old audit cleanup evidence absent |
| SEC-20 | none | admin auth/bind/CSRF/session/risky endpoints absent |
| SEC-21 | none | off-VDS custody, sentinel decrypt/pairing absent |
| SEC-22 | 159–161 current boot graph/journal | no staged reboot, post-reboot real traffic/login proof |

Evidence limitation: audit supports fresh installer-managed layouts and refuses
legacy at lines23–27. Its Caddy/singbox capability masks at109 allow respectively
NET_BIND_SERVICE and NET_RAW; these are not proof of current product's stricter
identity policy. Do not automatically apply it unchanged to the deployed panel.
Line74 hashes installed files without bounding reads; it is not a resource-peak
measurement. Lines50–54 execute nft under unshare; read-only inventory here never
executed that collector. Existing audit should be extended centrally by Lead
through reviewed contracts, not copied into a second framework.

Required next evidence: approved nonproduction Linux environment; pinned launcher
and current layout/identity contract; then collect missing operations above and
record observed/not_run per ID. No production access or state change occurred.