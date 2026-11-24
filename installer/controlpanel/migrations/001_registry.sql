CREATE TABLE schema_migrations (
  version       INTEGER PRIMARY KEY,
  sha256        TEXT NOT NULL,
  applied_at    TEXT NOT NULL
);

CREATE TABLE users (
  id                   TEXT NOT NULL PRIMARY KEY,
  login                TEXT NOT NULL UNIQUE COLLATE BINARY,
  kind                 TEXT NOT NULL DEFAULT 'regular' CHECK(kind IN ('regular','service')),
  protected            INTEGER NOT NULL DEFAULT 0 CHECK(protected IN (0,1)),
  source               TEXT NOT NULL DEFAULT 'panel' CHECK(source IN ('panel','legacy_import','installer','recovery')),
  display_name         TEXT NOT NULL,
  status               TEXT NOT NULL CHECK(status IN
    ('provisioning','active','disabled','deleting','deleted','reconcile_required')),
  created_at           TEXT NOT NULL,
  updated_at           TEXT NOT NULL,
  deleted_at           TEXT,
  row_version          INTEGER NOT NULL DEFAULT 1 CHECK(row_version > 0),
  -- Точный формат/длина логина проверяется по реальному parser v0.3.6.
  -- Не вставлять старый CHECK(3..32) / COLLATE NOCASE / LOWER(login).
  CHECK(length(display_name) BETWEEN 1 AND 80),
  CHECK((login = 'master_user' AND kind = 'service' AND protected = 1) OR
        (login <> 'master_user' AND kind = 'regular' AND protected = 0)),
  CHECK(protected = 0 OR status NOT IN ('disabled','deleting','deleted'))
);

CREATE TABLE credentials (
  id             TEXT NOT NULL PRIMARY KEY,
  user_id        TEXT NOT NULL REFERENCES users(id),
  secret_version INTEGER NOT NULL CHECK(secret_version > 0),
  cipher_alg     TEXT NOT NULL CHECK(cipher_alg = 'AES-256-GCM'),
  nonce          BLOB NOT NULL CHECK(typeof(nonce) = 'blob' AND length(nonce) = 12),
  ciphertext     BLOB NOT NULL CHECK(typeof(ciphertext) = 'blob' AND length(ciphertext) > 16),
  key_version    INTEGER NOT NULL CHECK(key_version > 0),
  created_at     TEXT NOT NULL,
  rotated_at     TEXT,
  revoked_at     TEXT,
  UNIQUE(user_id, secret_version), UNIQUE(user_id, id), UNIQUE(key_version, nonce)
);

CREATE TABLE user_current_credentials (
  user_id         TEXT NOT NULL PRIMARY KEY REFERENCES users(id),
  credential_id   TEXT NOT NULL UNIQUE,
  updated_at      TEXT NOT NULL,
  FOREIGN KEY(user_id, credential_id) REFERENCES credentials(user_id, id)
);

CREATE TABLE profile_templates (
  id             TEXT NOT NULL PRIMARY KEY,
  slug           TEXT NOT NULL UNIQUE,
  name           TEXT NOT NULL,
  transport      TEXT NOT NULL CHECK(transport IN ('naive_https')),
  enabled        INTEGER NOT NULL CHECK(enabled IN (0,1))
);

CREATE TABLE template_revisions (
  id             TEXT NOT NULL PRIMARY KEY,
  template_id    TEXT NOT NULL REFERENCES profile_templates(id),
  semver         TEXT NOT NULL,
  client_family  TEXT NOT NULL CHECK(client_family IN ('sfa')),
  min_version    TEXT NOT NULL,
  max_version    TEXT,
  body_json      TEXT NOT NULL,
  sha256         TEXT NOT NULL,
  status         TEXT NOT NULL CHECK(status IN ('draft','candidate','approved','retired')),
  created_at     TEXT NOT NULL,
  approved_at    TEXT,
  UNIQUE(template_id,semver)
);

CREATE TABLE user_profiles (
  id                    TEXT NOT NULL PRIMARY KEY,
  user_id               TEXT NOT NULL REFERENCES users(id),
  template_revision_id  TEXT NOT NULL REFERENCES template_revisions(id),
  target_client         TEXT NOT NULL,
  last_issued_at        TEXT,
  UNIQUE(user_id, target_client)
);

CREATE TABLE nodes (
  id                 TEXT NOT NULL PRIMARY KEY,
  alias              TEXT NOT NULL UNIQUE,
  role               TEXT NOT NULL CHECK(role IN ('ingress','egress')),
  hostname_ref       TEXT,
  last_seen_at       TEXT,
  observed_source    TEXT,
  checked_at         TEXT,
  stale_after        TEXT,
  health             TEXT NOT NULL DEFAULT 'unknown',
  row_version        INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE operations (
  id                 TEXT NOT NULL PRIMARY KEY,
  actor_id           TEXT NOT NULL,
  kind               TEXT NOT NULL,
  target_type        TEXT,
  target_id          TEXT,
  status             TEXT NOT NULL CHECK(status IN
    ('queued','running','verifying','succeeded','failed',
     'rollback_running','rolled_back','reconcile_required','cancelled')),
  idempotency_key    TEXT NOT NULL,
  request_hash       TEXT NOT NULL,
  expected_version   INTEGER,
  error_code         TEXT,
  correlation_id     TEXT NOT NULL,
  started_at         TEXT,
  finished_at        TEXT,
  created_at         TEXT NOT NULL,
  UNIQUE(actor_id, idempotency_key)
);

CREATE TABLE operation_steps (
  operation_id       TEXT NOT NULL REFERENCES operations(id),
  step_no            INTEGER NOT NULL,
  step_name          TEXT NOT NULL,
  state              TEXT NOT NULL,
  before_hash        TEXT,
  after_hash         TEXT,
  evidence_ref       TEXT,
  error_code         TEXT,
  started_at         TEXT NOT NULL,
  finished_at        TEXT,
  PRIMARY KEY(operation_id,step_no)
);

CREATE TABLE config_revisions (
  id                  TEXT NOT NULL PRIMARY KEY,
  node_id             TEXT NOT NULL REFERENCES nodes(id),
  generation          INTEGER NOT NULL,
  managed_hash_before TEXT,
  managed_hash_after  TEXT NOT NULL,
  snapshot_ref        TEXT NOT NULL,
  operation_id        TEXT NOT NULL REFERENCES operations(id),
  state               TEXT NOT NULL,
  applied_at          TEXT,
  UNIQUE(node_id,generation)
);

CREATE TABLE audit_runs (
  id                 TEXT NOT NULL PRIMARY KEY,
  script_version     TEXT NOT NULL,
  operation_id       TEXT REFERENCES operations(id),
  started_at         TEXT NOT NULL,
  finished_at        TEXT,
  summary            TEXT NOT NULL,
  coverage_hash      TEXT
);

CREATE TABLE audit_checks (
  audit_id           TEXT NOT NULL REFERENCES audit_runs(id),
  check_id           TEXT NOT NULL,
  severity           TEXT NOT NULL,
  status             TEXT NOT NULL CHECK(status IN
    ('pass','fail','warn','unknown','not_run','not_applicable')),
  observed_at        TEXT,
  evidence_redacted  TEXT,
  remediation_hint   TEXT,
  PRIMARY KEY(audit_id,check_id)
);

CREATE TABLE backups (
  id                 TEXT NOT NULL PRIMARY KEY,
  created_at         TEXT NOT NULL,
  format_version     INTEGER NOT NULL,
  encrypted_path     TEXT NOT NULL,
  sha256             TEXT NOT NULL,
  size_bytes         INTEGER NOT NULL,
  source_generation  INTEGER NOT NULL,
  verified_at        TEXT,
  status             TEXT NOT NULL CHECK(status IN
    ('created','verified','unusable','expired','deleted'))
);

CREATE TABLE admin_accounts (
  id                 TEXT NOT NULL PRIMARY KEY,
  username           TEXT NOT NULL UNIQUE,
  password_hash      TEXT NOT NULL,
  disabled           INTEGER NOT NULL DEFAULT 0 CHECK(disabled IN (0,1)),
  created_at         TEXT NOT NULL,
  last_login_at      TEXT
);

CREATE TABLE admin_sessions (
  id                 TEXT NOT NULL PRIMARY KEY,
  admin_id           TEXT NOT NULL REFERENCES admin_accounts(id),
  token_hash         TEXT NOT NULL UNIQUE,
  expires_at         TEXT NOT NULL,
  revoked_at         TEXT,
  last_seen_at       TEXT
);

CREATE TABLE legacy_migration_runs (
  id             TEXT NOT NULL PRIMARY KEY,
  phase          TEXT NOT NULL CHECK(phase IN ('inspect','planned','approved','importing','verified_cutover','rolled_back','reconcile_required')),
  source_hashes  TEXT NOT NULL,  -- JSON redacted refs/digests, never credentials
  started_at     TEXT NOT NULL,
  approved_at    TEXT,
  finished_at    TEXT,
  report_ref     TEXT,
  status         TEXT NOT NULL
);

CREATE TABLE legacy_migration_items (
  run_id            TEXT NOT NULL REFERENCES legacy_migration_runs(id),
  item_no           INTEGER NOT NULL,
  source_kind       TEXT NOT NULL,
  login_exact       TEXT COLLATE BINARY,
  finding_code      TEXT NOT NULL,
  resolution        TEXT,
  imported_user_id  TEXT REFERENCES users(id),
  evidence_hash     TEXT,
  PRIMARY KEY(run_id,item_no)
);

CREATE TABLE legacy_secret_artifacts (
  id                TEXT NOT NULL PRIMARY KEY,
  source_kind       TEXT NOT NULL,
  path_ref          TEXT NOT NULL,
  file_hash         TEXT,
  sensitivity       TEXT NOT NULL,
  disposition       TEXT NOT NULL DEFAULT 'inventory_only',
  last_verified_at  TEXT
);

CREATE INDEX idx_users_status_created ON users(status,created_at);
CREATE INDEX idx_users_kind_status ON users(kind,status);
CREATE INDEX idx_operations_status_created ON operations(status,created_at);
CREATE INDEX idx_operations_target ON operations(target_type,target_id,created_at);
CREATE INDEX idx_credential_user ON credentials(user_id,secret_version);
CREATE INDEX idx_audit_started ON audit_runs(started_at);
CREATE INDEX idx_backups_created ON backups(created_at);


CREATE TRIGGER users_immutable_identity BEFORE UPDATE OF id, login, kind, protected ON users
WHEN NEW.id <> OLD.id OR NEW.login <> OLD.login OR NEW.kind <> OLD.kind OR NEW.protected <> OLD.protected
BEGIN
  SELECT RAISE(ABORT, 'immutable user identity');
END;

CREATE TRIGGER users_keep_history BEFORE DELETE ON users
BEGIN
  SELECT RAISE(ABORT, 'use a tombstone');
END;

CREATE TRIGGER regular_capacity_insert BEFORE INSERT ON users
WHEN NEW.kind = 'regular' AND NEW.status <> 'deleted'
 AND (SELECT count(*) FROM users WHERE kind = 'regular' AND status <> 'deleted') >= 100
BEGIN
  SELECT RAISE(ABORT, 'user capacity reached');
END;

CREATE TRIGGER users_keep_tombstone BEFORE UPDATE OF status ON users
WHEN OLD.status = 'deleted' AND NEW.status <> 'deleted'
BEGIN
  SELECT RAISE(ABORT, 'deleted user is immutable');
END;
