// Package migrations contains the immutable schema distributed with the controller.
package migrations

import _ "embed"

//go:embed 001_registry.sql
var Registry string

//go:embed 002_vault_identity.sql
var VaultIdentity string

//go:embed 003_migration_documents.sql
var MigrationDocuments string

//go:embed 004_profile_issuance.sql
var ProfileIssuance string
