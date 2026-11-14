# W8 snapshot binding inventory — 2/2

Read-only source inventory and proposal, original HEAD985e04a context. No SQL
executed against owner data, no new crypto/journal/schema/shared changes.
W8→W9→W9.1 order acknowledged; W9.1 remains0/6, shared E1 requires G9.1.
Failed fixes0. Lead must freeze implementation after independent inventories.

## Canonical schema and binding sources

Paths below relative to installer/controlpanel unless noted.
- migrations/001_registry.sql:1 schema_migrations(version,sha256,applied_at).
  internal/storage/registry.go:110–134 embeds seven exact migration scripts,
  compares stored SHA256 per version and rejects mismatch; schema is7. Do not
  compare only MAX(version) or invoke migrating Open on an untrusted snapshot
  during verification. Validate immutable source bytes/checksums read-only.
- 001:7 users(id,login,kind,protected,source,display_name,status,created_at,
  updated_at,deleted_at,row_version); login UNIQUE COLLATE BINARY. Status values
  provisioning/active/disabled/deleting/deleted/reconcile_required. Protected
  master_user is service, may not be disabled/deleting/deleted. row_version is
  per-user CAS, not installation generation.
- 001:28 credentials(id,user_id,secret_version,cipher_alg,nonce,ciphertext,
  key_version,created_at,rotated_at,revoked_at), AES-256-GCM, unique nonce per key
  and user+secret_version. 001:42 user_current_credentials(user_id,credential_id,
  updated_at) has composite FK to the same user's credential. Keep revoked
  history, current mapping and tombstones, not merely active credentials.
- 002:1 vault_identity(singleton=1,key_version,nonce,ciphertext).
  registry.go:138–160 authenticates marker with Binding user !registry-key-check,
  SecretVersion1/current KeyVersion, plaintext vpn-control registry key v1.
  :168–184 authenticates existing credential rows for initial key identity.
  :345–356 selected current credential decrypt binds user/version/key version.
  Reuse canonical vault code for verification, never output marker/key/secrets.
- 001:94 operations(id,actor_id,kind,target_type,target_id,status,idempotency_key,
  request_hash,expected_version,error_code,correlation_id,started_at,finished_at,
  created_at); UNIQUE(actor_id,idempotency_key). Unfinished states queued/running/
  verifying/rollback_running/reconcile_required; terminal succeeded/failed/
  rolled_back/cancelled. Own backup operation must be classified explicitly.
- 001:114 operation_steps(operation_id,step_no,step_name,state,before_hash,
  after_hash,evidence_ref,error_code,started_at,finished_at). state is not a
  constrained substitute for operations.status; inspect intents separately.
- 005:1 user_mutations(operation_id,owner_run,before_status,after_status,
  old_credential_id,new_credential_id,reason,no_change). A prepared rotation can
  have old and new credentials before current mapping switches; no rule that
  every unrevoked credential must be current.
- Other schema1 tables: profile_templates,template_revisions,user_profiles,nodes,
  config_revisions,audit_runs,audit_checks,backups,admin_accounts,admin_sessions,
  legacy_migration_runs,legacy_migration_items,legacy_secret_artifacts. Migration3
  adds legacy_migration_documents,4 profile_issuance,6 routing variants rebuilt
  by7 profile panel DNS. Their full normative columns/FKs remain in those SQL
  files; verification must cover all tables, not a hand-copied subset here.
- 001:128 config_revisions has generation per node, managed_hash_before/after,
  snapshot_ref,operation_id,state,applied_at; no global registry-generation column.
  001:163 backups includes source_generation, verified_at and statuses created/
  verified/unusable/expired/deleted. Metadata/list is not snapshot implementation.

## Existing producer and writer boundary

installer/g3_snapshot.py:46–47 opens common /run/lock/empire-vpn.lock with LOCK_EX;
:48 rejects pending.json/user-rollback.json/return-intent.json/panel-auth-pending.json.
:49–68 inventories managed auth/Caddy/manifest/clients/profiles plus optional
wrapper/unit/ACME/vault.key; records owner/group/mode/content hash/xattr hashes.
:77–84 copies state.db through SQLite online backup from mode=ro source,
checks integrity and changes destination journal_mode=DELETE. Do NOT replace
with raw DB copy or include live WAL/SHM as independent restore files.
:85–94 compares inventory before/after but DB was excluded from that inventory;
metadata generation :88 is manifest.panel_generation, not DB revision proof.

cmd/vpnctl/lock_linux.go:12–23 canonical installationLock uses flock;
create_linux.go:85–87 enters it before owned installation work. Reuse this
boundary and recovery admission, do not reacquire same flock through another FD
inside a caller already holding it. Public snapshot still acquires the lock.
installer/owned_auth.py:80–84 checks intent absence and matching owner run plus
manifest.panel_generation; :133 advances file generation; :142–147 persists
existing panel-auth intent under caller's global flock. Caddy worker
cmd/vpnctl/caddy_create_linux.go:185–207 observes generation and prepares runtime
and file intent; prepared.json is not a database table. Need reject unresolved
prepared operation directories/apply intents in addition to unfinished SQL rows.

## Candidate read-only queries / no guessed equality

These reference actual schema; run only on an isolated online-backup copy after
safe staging, not owner production data during this inventory:

```sql
PRAGMA integrity_check;
PRAGMA foreign_key_check;
SELECT version,sha256 FROM schema_migrations ORDER BY version;
SELECT id,kind,status FROM operations
 WHERE status IN ('queued','running','verifying','rollback_running','reconcile_required');
SELECT key_version FROM vault_identity WHERE singleton=1;
SELECT u.id FROM users u LEFT JOIN user_current_credentials x ON x.user_id=u.id
 LEFT JOIN credentials c ON c.id=x.credential_id AND c.user_id=x.user_id
 WHERE u.status IN ('active','disabled') AND (c.id IS NULL OR c.revoked_at IS NOT NULL);
```

Do not add `SELECT generation FROM registry` or compare user row_version to
manifest generation. Separate source observations: owner run, manifest generation,
managed/runtime hashes, migration checksums, per-user CAS/current credential
versions and operation admission, captured under common writer. API session/
issuance writes may exist outside installation mutation lock; Lead must define
which registry snapshot consistency needs SQLite transaction semantics and which
observations require lock, without freezing auth globally by assumption.

Proposal: existing operation/admission + writer context wraps inventory and
online backup; compute staged DB hash and attach schema/checksums plus explicit
revision observations to authenticated metadata under reviewed format contract.
Verify vault marker and credential references through canonical code; wrong-key
or unfinished/apply intent fails. Add real copy tests for concurrent admission,
rotation-before-current-switch, missing/foreign current credentials, wrong vault,
WAL activity, checksum drift, protected master/case/revoked/tombstones and stale
restore reactivation. Artifact success alone never sets verified_at/status.
No universal scalar registry generation invented; no callback implemented here.