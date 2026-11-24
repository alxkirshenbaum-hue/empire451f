package storage

import (
	"context"
	"github.com/alxkirshenbaum-hue/empire451f/controlpanel/internal/vault"
)

// CaptureOwnedSnapshot binds the copied database to the observed installation key
// and canonical verified owner run. It neither opens nor migrates another registry.
func (r *Registry) CaptureOwnedSnapshot(ctx context.Context, directory, ownID, run string, expectedVault *vault.Vault) (SnapshotCapture, error) {
	if run == "" || expectedVault == nil {
		return SnapshotCapture{}, ErrSnapshotState
	}
	return r.captureSnapshot(ctx, directory, ownID, expectedVault, run)
}
