//go:build linux

package storage

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"sort"

	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// Manifest generations are supplied from fresh trusted manifest observations
// under the existing installation writer. They are NOT SQLite schema/user versions.
// CLI callers must recheck expected_generation against that observed manifest.
type RestorePlanBinding struct {
	OwnerRun                          string `json:"owner_run"`
	OwnBackupOperationID              string `json:"own_backup_operation_id,omitempty"`
	CurrentObservedManifestGeneration int64  `json:"current_observed_manifest_generation"`
	ExpectedManifestGeneration        int64  `json:"expected_manifest_generation"`
	BackupManifestGeneration          int64  `json:"backup_manifest_generation"`
	CurrentDBSHA256                   string `json:"current_db_sha256"`
	BackupDBSHA256                    string `json:"backup_db_sha256"`
}

type RestoreUserImpact struct {
	UserID                     string `json:"user_id"`
	CurrentStatus              string `json:"current_status"`
	BackupStatus               string `json:"backup_status"`
	Recreated                  bool   `json:"recreated"`
	Removed                    bool   `json:"removed"`
	CredentialMayChange        bool   `json:"credential_may_change"`
	MetadataMayChange          bool   `json:"metadata_may_change"`
	CredentialReactivationRisk bool   `json:"credential_reactivation_risk"`
}
type RestorePlanReport struct {
	Binding                  RestorePlanBinding  `json:"binding"`
	Changes                  []RestoreUserImpact `json:"changes"`
	ReactivationRiskCount    int                 `json:"reactivation_risk_count"`
	RecreatedCount           int                 `json:"recreated_count"`
	RemovedCount             int                 `json:"removed_count"`
	CredentialMayChangeCount int                 `json:"credential_may_change_count"`
	RequiredDowntime         string              `json:"required_downtime"`
}

type restorePlanUser struct {
	Status, CredentialID, Login, DisplayName, Kind string
	Protected                                      bool
	SecretVersion                                  int64
	Revoked                                        bool
}

// PlanRestore compares two immutable standalone captured DBs read-only. Obtain
// the current captured DB through canonical CaptureSnapshot under the writer;
// do not pass a mutable live WAL registry. Caller authenticates archive receipt,
// verifies source roots and holds both private staging trees immutable. The plan
// is not restore approval and does not assert that a changed ID means a new password.
func PlanRestore(ctx context.Context, currentPath, backupPath string, currentKey, backupKey *vault.Vault, b RestorePlanBinding) (out RestorePlanReport, err error) {
	if b.CurrentObservedManifestGeneration < 1 || b.ExpectedManifestGeneration != b.CurrentObservedManifestGeneration || b.BackupManifestGeneration < 1 || !hashPattern.MatchString(b.CurrentDBSHA256) || !hashPattern.MatchString(b.BackupDBSHA256) {
		return out, ErrSnapshotState
	}
	if _, err = InspectCapturedSnapshot(ctx, currentPath, currentKey, b.OwnerRun, ""); err != nil {
		return out, err
	}
	if _, err = InspectCapturedSnapshot(ctx, backupPath, backupKey, b.OwnerRun, b.OwnBackupOperationID); err != nil {
		return out, err
	}
	current, err := readRestorePlanUsers(ctx, currentPath, b.CurrentDBSHA256)
	if err != nil {
		return out, err
	}
	backup, err := readRestorePlanUsers(ctx, backupPath, b.BackupDBSHA256)
	if err != nil {
		return out, err
	}
	out.Binding = b
	out.Changes = []RestoreUserImpact{}
	out.RequiredDowntime = "Offline controlled restore; stop mutating control plane and preserve rollback DB/key pair"
	ids := map[string]bool{}
	for id := range current {
		ids[id] = true
	}
	for id := range backup {
		ids[id] = true
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	for _, id := range ordered {
		c, hasCurrent := current[id]
		a, hasBackup := backup[id]
		if hasCurrent && hasBackup && c == a {
			continue
		}
		impact := RestoreUserImpact{UserID: id, CurrentStatus: c.Status, BackupStatus: a.Status, Recreated: !hasCurrent && hasBackup, Removed: hasCurrent && !hasBackup}
		impact.MetadataMayChange = hasCurrent && hasBackup && (c.Login != a.Login || c.DisplayName != a.DisplayName || c.Kind != a.Kind || c.Protected != a.Protected)
		impact.CredentialMayChange = hasBackup && (!hasCurrent || c.CredentialID != a.CredentialID || c.SecretVersion != a.SecretVersion)
		impact.CredentialReactivationRisk = hasBackup && a.Status == "active" && !a.Revoked && (!hasCurrent || c.Status != "active" || c.Revoked || impact.CredentialMayChange)
		if impact.Recreated {
			out.RecreatedCount++
		}
		if impact.Removed {
			out.RemovedCount++
		}
		if impact.CredentialMayChange {
			out.CredentialMayChangeCount++
		}
		if impact.CredentialReactivationRisk {
			out.ReactivationRiskCount++
		}
		out.Changes = append(out.Changes, impact)
	}
	return out, nil
}

func readRestorePlanUsers(ctx context.Context, path, expected string) (result map[string]restorePlanUser, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, err
	}
	sha, err := restoreFileHash(f)
	if err != nil || sha != expected {
		return nil, ErrSnapshotState
	}
	db, err := sql.Open("sqlite3", snapshotURI(path)+"?mode=ro&_query_only=on&_busy_timeout=0")
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, db.Close()) }()
	rows, err := db.QueryContext(ctx, `SELECT u.id,u.status,u.login,u.display_name,u.kind,u.protected,COALESCE(c.id,''),COALESCE(c.secret_version,0),c.revoked_at IS NOT NULL FROM users u LEFT JOIN user_current_credentials x ON x.user_id=u.id LEFT JOIN credentials c ON c.id=x.credential_id ORDER BY u.id`)
	if err != nil {
		return nil, err
	}
	result = map[string]restorePlanUser{}
	for rows.Next() {
		var id string
		var user restorePlanUser
		if err = rows.Scan(&id, &user.Status, &user.Login, &user.DisplayName, &user.Kind, &user.Protected, &user.CredentialID, &user.SecretVersion, &user.Revoked); err != nil {
			rows.Close()
			return nil, err
		}
		if len(result) >= 10000 {
			rows.Close()
			return nil, ErrSnapshotState
		}
		result[id] = user
	}
	err = errors.Join(rows.Err(), rows.Close())
	if err != nil {
		return nil, err
	}
	after, e := os.Lstat(path)
	sha, e2 := restoreFileHash(f)
	if e != nil || e2 != nil || !os.SameFile(before, after) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || sha != expected {
		return nil, ErrSnapshotState
	}
	return result, nil
}
