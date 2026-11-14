# W8/2 safe audit evidence helper

This is a reusable implementation component, not full G8/SEC acceptance.
No production collection or destructive scenario was executed.

`pilot/w8_security_check.py::audit_safe(root_path, allowed_uid, layout=None)`
collects filesystem metadata under an explicit trusted installation root.
The existing root worker must supply its trusted layout; the default layout
names are synthetic/relative and do not guess a deployment ID or host paths.
The layout has exactly 13 fixed categories: auth, clients, manifest, profiles,
exports, backups, vault, SSH, WireGuard, database, snapshots, temporary files,
and logs. Missing surfaces and unknown root entries prevent a complete result.
This does not claim discovery of secrets outside the supplied installation root.

Every path component is opened descriptor-relative with O_NOFOLLOW; private
root ownership/mode, actual st_uid/st_mode, file type, hardlinks, bounded depth,
entry count and total observed size are checked. Root-owned sticky ancestors
are allowed for private local fixtures. No file content, manifest, database,
key, profile, audit log or hash is read. Evidence contains only fixed categories,
counts, sizes and fixed finding codes, never filenames, paths or exceptions.
Inventory is bounded at 512 visited entries, depth 16 and 500 MB observed bytes.
A partial result remains partial on missing, unsafe or oversized surfaces.
`serialize_safe_evidence` applies an exact field/value allowlist and 64 KiB cap.

The existing `security_audit.audit` private-file policy supplies the owner/mode
baseline. That whole collector is deliberately not called: it reads sensitive
files wholesale and requires a pinned launcher/live probes. `controlled_audit`
performs WG changes/restarts/reboots and is never imported or executed here.
No second daemon, alternative operation journal or runtime schema is created.
The helper does not parse SQLite, so schema-8 integrity is explicitly NOT_RUN.

| Checks | Safe result | Remaining evidence |
| --- | --- | --- |
| SEC-01..05 | not_run | Effective SSH, listeners, firewall, WG/routes and static fail-closed observations from approved existing collector |
| SEC-06 | skipped_destructive | Approved isolated WG-down leak drill |
| SEC-07..08 | not_run | Actual process namespace/capabilities, dependency graph and restart policy |
| SEC-09 | unknown if private metadata; fail on unsafe/oversize | Complete deployment layout, foreign-UID/proc-root negative tests and log redaction; metadata alone cannot pass SEC-09 |
| SEC-10..15 | not_run | Caddy/plugin/TLS/site/proxy/egress/time/resource observations |
| SEC-16 | not_run | Canonical schema-8 SQLite integrity/checksums and vault pairing |
| SEC-17..21 | not_run | Operation-bound backup age/verify/restore, auth negatives, retention, API security and sentinel pairing |
| SEC-22 | skipped_destructive | Approved staged reboot plus dependency integrity evidence |

Validation: local Linux WSL, PrivateNetwork=yes, synthetic temporary fixture
files only; `python3 -m unittest discover -s tests -p test_w8_security_fixtures.py`:
12 tests PASS. Includes content-read rejection, missing/unsafe/symlink/hardlink,
wrong UID/mode, root traversal, entry/size caps, unknown artifact, bounded JSON,
secret canary exclusion and honest 22-check statuses. No network or production
settings were changed. Worker/API/CLI journal integration remains main-owned.
