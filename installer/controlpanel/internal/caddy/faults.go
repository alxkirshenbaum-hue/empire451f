package caddy

// G5FailurePoints names the required post-step crash boundaries (§6.1).
// Runtime observers are supplied only by an isolated test runner; no environment
// variable or HTTP request enables them in an installed worker.
var G5FailurePoints = [...]string{
	"after_global_lock", "after_observed_preflight", "after_running_commit",
	"after_snapshot", "after_desired_stage", "after_candidate_render",
	"after_validate", "after_prepared_fsync", "after_apply", "after_fresh_verify",
	"after_verified_db_commit", "after_rollback_verify", "after_reconcile_required",
	"after_staging_cleanup",
}
