# W8 integration boundaries — first approved parallel round

Date: 2026-11-14. Lead baseline: 84c5262. Scope: implementation contract for
copy-only preparation; not G6/G7/G8 acceptance or production authorization.
Architecture & Roadmap concept 0.2 / LLD 1.1 remain normative.

## Reuse and ownership

Use existing SQLite operations/backups/audit tables, shared writer lock,
Prepared/apply/reconcile, g3_snapshot, owner envelope and RootDirectory harness.
No second queue, crypto protocol or service. Lead owns shared code and migration
numbers. SOL-A owns read-only artifact inspection and its fixtures; SOL-B owns
fixture policy checks/coverage and independent review. Neither may access VDS.

Existing envelope is RSA-OAEP-256/A256GCM. It remains the existing bounded G3
format, not a claim of a new general streaming backup implementation. Existing
helpers buffer payloads; W8 must measure or remove whole-archive buffering to
satisfy LLD M-006 before acceptance. Recipient private keys remain off VDS.

## Evidence levels and persisted states

- Artifact inspector output `artifact_check_passed`: actual bounded hash,
  manifest/path/member checks only. Caller-supplied digest is trusted only when
  sourced from an authenticated receipt. No extraction, decryption or restore.
- Envelope authenticity: existing helper decrypts with matching recipient;
  wrong key/tamper must fail. This alone does not bind SQLite/users/runtime.
- Registry consistency: online SQLite backup, integrity + foreign_key_check,
  repository migration checksums/version, credential references and vault key
  pairing; unfinished operations and prepared secrets cannot be ignored.
- Usable restore: isolated real stack accepts owner login and fresh connection
  of a pre-existing active profile, rejects revoked credentials, preserves exact
  login/master/protected/tombstones and validates managed Caddy configuration.
- G8: above evidence plus independent security review, retention/rotation and
  complete aggregate disk/RAM peaks, pinned full suite and gate review by Lead.

Do not invent persisted backup states: schema1 already has created, verified,
unusable, expired, deleted. Prototype outputs MUST NOT update `verified_at` or
status=verified. BKP-04 runtime implementation needs full LLD validation; E1
acceptance additionally needs the usable restore drill. Failures must retain
sanitized evidence and must never promote a backup based on tar/decrypt alone.

## Snapshot and serialization contract

1. The existing common writer excludes conflicting mutations. If caller already
   owns flock, it must pass an explicit protected internal context or invoke an
   unlocked inner helper; never reopen/reacquire the same lock through another
   file descriptor. Public snapshot entry still acquires the lock itself.
2. A backup operation cannot reject itself as an unfinished operation. Classify
   its own operation ID explicitly; reject other queued/running/verifying,
   rollback_running/reconcile_required and any prepared-secret/apply intent
   relevant to the snapshot. Check actual current schema, not invented tables.
3. Take SQLite through its online backup API, never copy a live DB file without
   WAL coordination. Couple captured registry revision/generation and managed
   files under the same writer boundary, then compare source observations.
4. Current G3 metadata.files excludes state.db and its generation comes from the
   installation manifest. Thus existing G3 tar validation CANNOT prove registry
   generation/credential consistency. Report `not_run` until a registry-backed
   callback is implemented and independently reviewed. No guessed SQL equality.
5. Bound reads, JSON metadata, member counts and total archive/logical sizes.
   Hash in chunks, retain descriptors rather than plaintext file bodies. Reject
   unsafe members/duplicates/traversal/sparse/links. GNU ACL/xattr/PAX metadata
   needs an explicit compatible allowlist and producer round-trip proof; a
   conservative PAX rejection must be reported as a compatibility limitation.
6. No unexpected archive member is silently trusted or restored. Database/vault
   and any other un-inventoried G3 members need explicit policies and integrity
   checks. Tar checksum is not cryptographic source authenticity.
7. Sandbox extraction and SQL opening are separate reviewed steps. Protect the
   complete parent path and file descriptor, not only a pre-open symlink check.
   Caller must use a private immutable staging directory until fd hardening is
   verified. Do not inspect actual owner archives in a worktree.

## BKP/API/CLI integration order

First ship copy helpers and review, then integrate BKP-01/04 through existing
operations (actor/idempotency/request hash/admission) and BKP-02/03 metadata.
BKP-05 is read-only with expected_generation and explicit credential-reactivation
risk/current-vs-backup comparison. No secret contents in response, argv or logs.
BKP-06 remains offline/test-only by default, requires explicit approval and
backup-before-restore; Web E1 must not expose actual restore. BKP-07 starts with
CAS-bound dry-run and cannot delete the minimum verified generations. Lead
freezes exact request/response/schema changes in a reviewed patch before wiring.

A stale snapshot cannot silently overwrite current users/passwords (including
user-created daria). Restore/rollback must export current active state first and
make any revoked-account reactivation visible. Preserve unmanaged configuration.

## Runtime and resource proof — initial-round historical prerequisites

Portable Python: app-bundled Python 3.12.14, SQLite 3.53.1, cryptography 50.0.2
executed on Windows by Lead; no runtime installation. Linux/systemd/CGO/network
namespace runner remains unconfirmed. hh-entry is production even when using a
RootDirectory: neither agent may use it. Portable PASS is not Linux identity or
real restore evidence. Production remains untouched by this parallel round.

Separate ceilings: additional disk <=500,000,000 bytes total across both nodes
(including WAL/backups/versions/temp/open deleted files), aggregate panel RAM
<=500,000,000 bytes across API/frontend/worker/helper descendants. Measure
memory.current/peak + RSS/PSS and allocated filesystem blocks over time; caps,
logical sizes and synthetic values do not prove these gates. Runtime scenarios
sharing one copy run sequentially; code/portable fixtures run in parallel.

## 2026-11-14 — canonical binding clarification (schema7, no new counter)

Reviewed source inventory: reports/W8_SNAPSHOT_BINDING_REVIEW.md (source6d92468,
integrated8202ed1). No universal scalar registry generation exists. Installation
manifest.panel_generation, per-user row_version, credential versions and per-node
config_revisions have distinct meanings and MUST NOT be equated. G3's old file
inventory omits state.db; archive inspection cannot close this gap.

Lead's callback must capture explicit common-writer observations (owner run,
manifest generation, managed/runtime hashes, pending/prepared intents) and staged
online SQLite snapshot hash, schema_migrations checksums and canonical vault
marker/current-credential binding. Use real vault_identity/key version and
canonical authentication logic; do not add an independent cryptographic verifier.
Inspect untrusted staged DB read-only before using Registry.Open: Open applies
migrations. No inferred SQL table/column or field called global generation.

The installation lock serializes managed mutations, not all auth/session/profile
issuance writes. SQLite's online-backup snapshot defines registry consistency;
state exactly which writer observations are protected by flock and which are
captured by SQLite. Reject other unfinished operations and prepared/file intents;
classify own backup ID rather than rejecting the backup itself. Do not assume
quiescent auth or persist verified merely from successful tar/decrypt.

Implementation and concurrent/WAL/rotation/wrong-key/stale-restore tests remain
open; this is a clarified integration contract, not a completed BKP feature.
W9.1 will reuse the accepted backup/restore interface AFTER W8/W9. G9 certifies
panel components; overall E1 additionally requires the six-item G9.1 matrix.

Current runtime qualification supersedes the initial unconfirmed-runner note: W8_LAB_QUALIFICATION_2026-11-14.md /774c07a confirms local systemd/RootDirectory/API/frontend/Go/Python proof. Full backup/restore and aggregate resource gates remain OPEN. Canonical-binding clarification independently reviewed SOL-B1/1, no blockers.

InspectSnapshot c4bf7bb validates only its own read-transaction view; that view ends on return. It cannot authorize a subsequently copied DB: actual backup must validate the captured SQLite image and bind file/writer observations to that capture, accounting for auth/session/issuance writes. No snapshot-copy consistency or verified state is implied by preflight success.
