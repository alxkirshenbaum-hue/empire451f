CREATE TABLE legacy_migration_documents (
  run_id TEXT NOT NULL REFERENCES legacy_migration_runs(id),
  kind TEXT NOT NULL CHECK(kind IN ('inspection','plan')),
  body TEXT NOT NULL,
  PRIMARY KEY(run_id, kind)
);

CREATE TRIGGER legacy_migration_document_immutable BEFORE UPDATE ON legacy_migration_documents
BEGIN
  SELECT RAISE(ABORT, 'migration document is immutable');
END;
