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