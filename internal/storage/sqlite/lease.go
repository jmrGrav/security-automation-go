package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

type LeaseRepository struct {
	db *DB
}

func NewLeaseRepository(db *DB) *LeaseRepository {
	return &LeaseRepository{db: db}
}

func (r *LeaseRepository) GetActiveLease(ctx context.Context, scopeID string, action string) (*models.Lease, error) {
	const op = "storage.sqlite.LeaseRepository.GetActiveLease"
	var l models.Lease
	err := r.db.Conn().QueryRowContext(ctx, `
		SELECT lease_id, owner, action, epoch_id, fencing_token, expires_at, created_at 
		FROM leases 
		WHERE scope_id = ? AND action = ? AND expires_at > CURRENT_TIMESTAMP
	`, scopeID, action).Scan(&l.ID, &l.Owner, &l.Action, &l.EpochID, &l.FencingToken, &l.ExpiresAt, &l.CreatedAt)

	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return &l, nil
}

func (r *LeaseRepository) AcquireLease(ctx context.Context, scopeID string, l models.Lease) error {
	const op = "storage.sqlite.LeaseRepository.AcquireLease"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := r.db.Conn().ExecContext(ctx, `
		INSERT INTO leases (scope_id, lease_id, owner, action, epoch_id, fencing_token, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, scopeID, l.ID, l.Owner, l.Action, l.EpochID, l.FencingToken, l.ExpiresAt)
	return apperr.Wrap(op, err)
}

func (r *LeaseRepository) RenewLease(ctx context.Context, scopeID string, leaseID string, owner string, epochID string, fencingToken int64, expiresAt time.Time) error {
	const op = "storage.sqlite.LeaseRepository.RenewLease"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}
	if scopeID == "" {
		return apperr.New(op, "scope_id is required")
	}
	if owner == "" {
		return apperr.New(op, "owner is required")
	}
	if epochID == "" {
		return apperr.New(op, "epoch_id is required")
	}
	res, err := r.db.Conn().ExecContext(ctx, `
		UPDATE leases
		SET expires_at = ?
		WHERE lease_id = ? AND scope_id = ? AND owner = ? AND epoch_id = ? AND fencing_token = ?
	`, expiresAt.UTC(), leaseID, scopeID, owner, epochID, fencingToken)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return apperr.Newf(op, "failed to renew lease %s: not found or owner/scope/epoch/fencing mismatch", leaseID)
	}
	return nil
}

func (r *LeaseRepository) ReleaseLease(ctx context.Context, scopeID string, leaseID string, owner string) error {
	const op = "storage.sqlite.LeaseRepository.ReleaseLease"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}
	res, err := r.db.Conn().ExecContext(ctx, "DELETE FROM leases WHERE lease_id = ? AND scope_id = ? AND owner = ?", leaseID, scopeID, owner)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		// This might be okay if already expired or released, but let's log it via the error if needed.
		// For Release, we might be more lenient, but let's stick to the owner check for safety.
	}
	return nil
}
