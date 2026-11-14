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

//go:embed 005_user_mutations.sql
var UserMutations string

//go:embed 006_profile_routing.sql
var ProfileRouting string

//go:embed 007_profile_panel_dns.sql
var ProfilePanelDNS string

//go:embed 008_maintenance.sql
var Maintenance string
