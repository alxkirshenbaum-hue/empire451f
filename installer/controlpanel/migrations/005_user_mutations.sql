CREATE TABLE user_mutations (
 operation_id TEXT PRIMARY KEY REFERENCES operations(id),
 owner_run TEXT NOT NULL REFERENCES legacy_migration_runs(id),
 before_status TEXT NOT NULL CHECK(before_status IN ('active','disabled')),
 after_status TEXT NOT NULL CHECK(after_status IN ('active','disabled','deleted')),
 old_credential_id TEXT NOT NULL REFERENCES credentials(id),
 new_credential_id TEXT NOT NULL REFERENCES credentials(id),
 reason TEXT NOT NULL,
 no_change INTEGER NOT NULL CHECK(no_change IN (0,1))
);
