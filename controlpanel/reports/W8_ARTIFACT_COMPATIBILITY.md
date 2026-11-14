# W8 producer compatibility design — 2/2

Base f6afe33; report-only design. No producer round-trip executed in this package.
No production/owner material, extraction, SQL or shared-helper changes.

## Observed producer contract

g3_snapshot.py inventories source files as uid/gid/stat.S_IMODE/contentSHA256/
map(xattrName -> SHA256(rawValue)). It copies paths with copy2/copystat and
chown/chmod; online SQLite backup is staged separately, excluded from files.
Metadata generation is installation manifest panel_generation, not registry proof.
Producer invokes GNU tar --acls --xattrs --numeric-owner -cpf, from files stage.
Thus ACL/xattr-capable extension records are expected; exact on-disk header keys,
encodings, order and duplicate behavior remain unobserved, not claimed measured.
Current inspector refuses every member.pax_headers and nonempty inventory xattrs;
this is conservative fail-closed prototype behavior, not producer compatibility.

## Minimal proposed extension policy (not implemented)

1. First use a new synthetic Linux directory, exact installed GNU tar version,
   command above and files with none/user xattrs/ACLs. Record raw extension header
   keys and byte encoding alongside Python tarfile effective descriptors. Avoid
   guessing representation from a decoded text PAX value: raw xattr can be binary.
2. Bounded preflight must inspect extension records before tarfile materializes
   them: aggregate PAX bytes, per-record bytes and count have explicit caps.
   Current 32MiB archive cap alone permits a large single extension allocation.
   Preserve 64KiB content hashing and 1MiB metadata cap; never retain archive.
3. Candidate allowlist for observed GNU output only: SCHILY.xattr.<exact-name>
   for names explicitly inventoried and policy-approved, plus observed
   SCHILY.acl.access/default representations. Timestamp-only mtime/atime/ctime
   may be accepted as bounded validated numeric informational fields after
   producer proof; they must not affect authorization or freshness.
4. Reject unknown/global extension keys, duplicate raw keys, GNU sparse keys,
   path/linkpath/size/uid/gid overrides and all link/device/FIFO types initially.
   This deliberately leaves long paths requiring path override unsupported.
   Do not relax effective path normalization, duplicates, regular-only content,
   exact uid/gid/mode or archive/logical/member bounds.
5. Compare SHA256 of exact reconstructed raw xattr bytes to inventory. Reject
   missing or extra attributes. Allow only exact policy-selected names; do not
   auto-restore security.capability, security.selinux or trusted.*. Such producer
   files require explicit reviewed support or refusal. ACLs must round-trip and
   be reconciled with POSIX mode and inventoried system.posix_acl_* hashes;
   otherwise refuse rather than treating textual ACL as equivalent raw bytes.
6. No PAX support grants extraction permission. Restore must separately use a
   private immutable parent chain, safe destination FD traversal/no overwrite,
   no links and explicit owner/mode/xattr application under sandbox identities.

Tests required: producer none/xattr/ACL positive round-trips; binary/NUL/non-UTF8
attribute values; tampered/missing/extra xattrs; duplicate PAX keys; unknown and
global keys; huge extensions/count; sparse; overrides including traversal via
PAX path; effective duplicate paths; ACL/mode mismatch; capability rejection;
unchanged bounded-read guard; no source-secret output and no writes on refusal.
Each successful support increment needs independent security review.

## Database and manifest binding gaps

state.db is currently an explicitly unchecked exception. Existing encrypted
archive authenticity binds archive bytes to a receipt but not source SQLite
consistency or generation. Lead must bind online-backup DB hash/schema migration
checksums and registry revision to managed-file inventory under common writer
boundary; include DB in authenticated metadata and compare source observations.
Check integrity/foreign keys, exact migrations/checksums, credential references,
vault pairing, unfinished operations/prepared-secret intents; own backup op ID
must be classified explicitly. Never invent a generation-column equality.
Preserve protected master, case-sensitive login, current/revoked/tombstones,
unmanaged config and owner credentials; stale restore needs current-state
comparison and explicit reactivation risk before separately authorized execution.
Until real callback/stack evidence exists, registry_consistency=not_run and
artifact_check_passed cannot promote persisted backup status to verified.

Steps: 1 producer/inspector gap analysis done; 2 bounded allowlist/test/binding
proposal done. No tests run for this report-only package; failed-fix count0.
## Implemented limited raw admission revision

Before tarfile, same opened FD now undergoes bounded physical-header scan:
512-byte records, unsigned checksum, octal/nonnegative base256 sizes, logical/
physical bounds, zero padding, mandatory two end records and zero trailing data.
Only regular/directory types admitted; x/g/L/K/sparse and all other types rejected
before parser extension allocation. This does not add PAX/xattr compatibility.
Private immutable caller staging remains mandatory; no TOCTOU completion claim.

Portable verification: Python3.12.14 Ran10 tests OK (0.933s), no skips. New cases:
12 raw negatives with tarfile.open mocked to fail if reached (five extension
kinds, huge octal, negative base256, invalid octal, truncated padding, nonzero
padding, large PAX and checksum tamper), plus nonnegative base256 positive.
Existing actual bounded-read guard still passes. GNU producer compatibility,
registry binding and Linux stack/resource gates remain pending. Failed-fix0.
Steps design/implementation+negatives/portable verification:3/3 complete.
## Raw boundary fixture follow-up

Read original W9.1 integration/PLAN/PROGRESS and parent spec updates: order
W8 -> W9 -> W9.1; G9 panel components only, E1 requires G9.1 (0/6).
No W9.1 implementation in this package.

Test-only additions exercise raw member-count exact/over limit and logical-size
exact/over limit directly, separating logical from physical archive bounds.
Three end-record negatives (missing second record, nonzero trailing data,
nonzero second record) assert high-level parser never reached. Existing bounded
read fixtures remain active. Windows Python3.12.14 Ran11 tests OK (1.069s), no
skips. No shared code changed, no Linux heavy workload. Package design/tests/
verification3/3; separate failed-fix counter0.