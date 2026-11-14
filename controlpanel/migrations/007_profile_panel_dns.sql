ALTER TABLE profile_routing_variants RENAME TO profile_routing_variants_v1;
CREATE TABLE profile_routing_variants (
 source_revision_id TEXT NOT NULL REFERENCES template_revisions(id),
 variant TEXT NOT NULL CHECK(variant IN ('base','ru_download_manager')),
 policy_version INTEGER NOT NULL CHECK(policy_version>0),
 revision_id TEXT NOT NULL UNIQUE REFERENCES template_revisions(id),
 PRIMARY KEY(source_revision_id,variant,policy_version)
);
INSERT INTO profile_routing_variants(source_revision_id,variant,policy_version,revision_id)
 SELECT source_revision_id,variant,1,revision_id FROM profile_routing_variants_v1;
DROP TABLE profile_routing_variants_v1;
