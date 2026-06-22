package sqlite

import (
	"context"
	"database/sql"
	"errors"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/trustednetworks"
)

// CrowdSecAllowlistStatusStore is the SQLite-backed implementation of
// trustednetworks.CrowdSecStatusStore. The root-owned cf-allowlist-sync
// helper is the sole writer (it is the only process permitted to read
// /etc/crowdsec/local_api_credentials.yaml and invoke cscli); the cf-sync
// daemon and the UI are read-only consumers of this table.
type CrowdSecAllowlistStatusStore struct {
	db *DB
}

// NewCrowdSecAllowlistStatusStore returns a CrowdSecAllowlistStatusStore
// backed by db.
func NewCrowdSecAllowlistStatusStore(db *DB) *CrowdSecAllowlistStatusStore {
	return &CrowdSecAllowlistStatusStore{db: db}
}

var _ trustednetworks.CrowdSecStatusStore = (*CrowdSecAllowlistStatusStore)(nil)

// GetCrowdSecAllowlistStatus returns the most recently persisted status for
// allowlistName. ok is false if the helper has never run (or has never run
// against this allowlist name).
func (s *CrowdSecAllowlistStatusStore) GetCrowdSecAllowlistStatus(ctx context.Context, allowlistName string) (trustednetworks.CrowdSecAllowlistStatus, bool, error) {
	const op = "storage.sqlite.CrowdSecAllowlistStatusStore.GetCrowdSecAllowlistStatus"
	row := s.db.Conn().QueryRowContext(ctx, `
		SELECT allowlist_name, configured, auth_ok, last_sync_at, last_error,
		       desired_count, current_count, drift_count, mode
		FROM crowdsec_allowlist_status
		WHERE allowlist_name = ?
	`, allowlistName)

	var (
		status     trustednetworks.CrowdSecAllowlistStatus
		configured int
		authOK     int
		lastSyncAt sql.NullTime
	)
	err := row.Scan(&status.AllowlistName, &configured, &authOK, &lastSyncAt, &status.LastError,
		&status.DesiredCount, &status.CurrentCount, &status.DriftCount, &status.Mode)
	if errors.Is(err, sql.ErrNoRows) {
		return trustednetworks.CrowdSecAllowlistStatus{}, false, nil
	}
	if err != nil {
		return trustednetworks.CrowdSecAllowlistStatus{}, false, apperr.Wrap(op, err)
	}
	status.Configured = configured != 0
	status.AuthOK = authOK != 0
	if lastSyncAt.Valid {
		status.LastSyncAt = lastSyncAt.Time.UTC()
	}
	return status, true, nil
}

// PutCrowdSecAllowlistStatus upserts the status row for
// status.AllowlistName. Called exclusively by the cf-allowlist-sync helper
// after each reconcile attempt (success or failure).
func (s *CrowdSecAllowlistStatusStore) PutCrowdSecAllowlistStatus(ctx context.Context, status trustednetworks.CrowdSecAllowlistStatus) error {
	const op = "storage.sqlite.CrowdSecAllowlistStatusStore.PutCrowdSecAllowlistStatus"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}

	var lastSyncAt any
	if !status.LastSyncAt.IsZero() {
		lastSyncAt = status.LastSyncAt.UTC()
	}

	_, err := s.db.Conn().ExecContext(ctx, `
		INSERT INTO crowdsec_allowlist_status
			(allowlist_name, configured, auth_ok, last_sync_at, last_error,
			 desired_count, current_count, drift_count, mode)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(allowlist_name) DO UPDATE SET
			configured    = excluded.configured,
			auth_ok       = excluded.auth_ok,
			last_sync_at  = excluded.last_sync_at,
			last_error    = excluded.last_error,
			desired_count = excluded.desired_count,
			current_count = excluded.current_count,
			drift_count   = excluded.drift_count,
			mode          = excluded.mode,
			updated_at    = CURRENT_TIMESTAMP
	`,
		status.AllowlistName, boolToInt(status.Configured), boolToInt(status.AuthOK), lastSyncAt, status.LastError,
		status.DesiredCount, status.CurrentCount, status.DriftCount, status.Mode,
	)
	return apperr.Wrap(op, err)
}
