CREATE TABLE profile_routing_variants (
 source_revision_id TEXT NOT NULL REFERENCES template_revisions(id),
 variant TEXT NOT NULL CHECK(variant IN ('base','ru_download_manager')),
 revision_id TEXT NOT NULL UNIQUE REFERENCES template_revisions(id),
 PRIMARY KEY(source_revision_id,variant)
);
ALTER TABLE profile_issuance ADD COLUMN target_client TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE profile_issuance ADD COLUMN routing_variant TEXT NOT NULL DEFAULT 'legacy';
ALTER TABLE profile_issuance ADD COLUMN revision_id TEXT;
ALTER TABLE profile_issuance ADD COLUMN profile_sha256 TEXT;
