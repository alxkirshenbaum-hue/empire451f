CREATE TABLE maintenance_intents (
 operation_id TEXT PRIMARY KEY REFERENCES operations(id),
 owner_run TEXT NOT NULL REFERENCES legacy_migration_runs(id),
 request_json TEXT NOT NULL,
 label TEXT NOT NULL DEFAULT '',
 backup_id TEXT,
 key_id TEXT NOT NULL DEFAULT '',
 expected_hash TEXT NOT NULL DEFAULT '',
 evidence_json TEXT
);
CREATE TABLE backup_details (
 backup_id TEXT PRIMARY KEY REFERENCES backups(id),
 operation_id TEXT NOT NULL UNIQUE REFERENCES operations(id),
 owner_run TEXT NOT NULL REFERENCES legacy_migration_runs(id),
 label TEXT NOT NULL,
 key_id TEXT NOT NULL,
 manifest_sha256 TEXT NOT NULL,
 verification_operation TEXT REFERENCES operations(id),
 verification_evidence TEXT,
 restore_tested_at TEXT,
 restore_operation TEXT REFERENCES operations(id)
);
CREATE TABLE backup_configuration (
 singleton INTEGER PRIMARY KEY CHECK(singleton=1),
 key_id TEXT NOT NULL,
 enabled INTEGER NOT NULL CHECK(enabled IN(0,1))
);
