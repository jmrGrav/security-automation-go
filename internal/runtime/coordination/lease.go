package coordination

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/storage"
)

// LeaseManager handles exclusive execution ownership.
type LeaseManager struct {
	mu      sync.Mutex
	store   *state.StateStore
	expiry  time.Duration
	scopeID string
	leases  storage.LeaseStore
}

func NewLeaseManager(store *state.StateStore, expiry time.Duration) *LeaseManager {
	return &LeaseManager{
		store:  store,
		expiry: expiry,
	}
}

func (m *LeaseManager) WithLeaseStore(scopeID string, leases storage.LeaseStore) *LeaseManager {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.scopeID = scopeID
	m.leases = leases
	return m
}

func (m *LeaseManager) HasPersistentLeaseStore() bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.scopeID != "" && m.leases != nil
}

// Acquire attempts to claim the execution lease for a new epoch.
func (m *LeaseManager) Acquire(ctx context.Context, owner, action string, schedulerRunID string) (*models.Lease, *models.Epoch, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	const op = "runtime.coordination.Acquire"

	curState, err := m.store.Load()
	if err != nil {
		return nil, nil, apperr.Wrap(op, err)
	}

	// 1. Check existing lease
	var activeLease *models.Lease
	if m.leases != nil {
		lease, err := m.leases.GetActiveLease(ctx, m.scopeID, action)
		if err != nil {
			return nil, nil, apperr.Wrap(op, err)
		}
		activeLease = lease
	} else {
		if action == "rollback" {
			activeLease = curState.ActiveRollbackLease
		} else {
			activeLease = curState.ActiveLease
		}
	}

	if activeLease != nil && !activeLease.IsExpired() {
		if activeLease.Owner != owner {
			return nil, nil, apperr.Newf(op, "lease owned by %s (action: %s)", activeLease.Owner, activeLease.Action)
		}
		// Same owner, allow re-acquisition/extension (idempotent)
	}

	// 2. Generation of new epoch
	newEpoch := models.Epoch{
		ID:             fmt.Sprintf("ep-%d", time.Now().UnixNano()),
		ParentID:       curState.CurrentEpoch.ID,
		Generation:     curState.CurrentEpoch.Generation + 1,
		SchedulerRunID: schedulerRunID,
		CreatedAt:      time.Now().UTC(),
	}

	newLease := &models.Lease{
		ID:           fmt.Sprintf("lease-%s", newEpoch.ID),
		Owner:        owner,
		Action:       action,
		EpochID:      newEpoch.ID,
		FencingToken: newEpoch.Generation, // Simple monotonic fencing token
		ExpiresAt:    time.Now().Add(m.expiry),
		CreatedAt:    time.Now().UTC(),
	}

	if m.leases != nil {
		if activeLease != nil && activeLease.Owner == owner && activeLease.ID != newLease.ID {
			if err := m.leases.ReleaseLease(ctx, m.scopeID, activeLease.ID, activeLease.Owner); err != nil {
				return nil, nil, apperr.Wrap(op, err)
			}
		}
		if err := m.leases.AcquireLease(ctx, m.scopeID, *newLease); err != nil {
			return nil, nil, apperr.Wrap(op, err)
		}
	}

	// 3. Persist state mirror
	curState.CurrentEpoch = newEpoch
	if action == "rollback" {
		curState.ActiveRollbackLease = newLease
	} else {
		curState.ActiveLease = newLease
	}

	if err := m.store.Save(curState); err != nil {
		return nil, nil, apperr.Wrap(op, err)
	}

	return newLease, &newEpoch, nil
}

// Release releases an owned lease.
func (m *LeaseManager) Release(ctx context.Context, leaseID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	const op = "runtime.coordination.Release"

	curState, err := m.store.Load()
	if err != nil {
		return apperr.Wrap(op, err)
	}

	var lease *models.Lease
	if curState.ActiveLease != nil && curState.ActiveLease.ID == leaseID {
		lease = curState.ActiveLease
		curState.ActiveLease = nil
	} else if curState.ActiveRollbackLease != nil && curState.ActiveRollbackLease.ID == leaseID {
		lease = curState.ActiveRollbackLease
		curState.ActiveRollbackLease = nil
	} else {
		return nil // Already released or owned by someone else
	}

	if m.leases != nil {
		if err := m.leases.ReleaseLease(ctx, m.scopeID, leaseID, lease.Owner); err != nil {
			return apperr.Wrap(op, err)
		}
	}

	return m.store.Save(curState)
}

func (m *LeaseManager) Renew(ctx context.Context, leaseID string, ttl time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	const op = "runtime.coordination.Renew"
	if ttl <= 0 {
		ttl = m.expiry
	}
	if ttl <= 0 {
		return apperr.New(op, "lease ttl must be positive")
	}

	curState, err := m.store.Load()
	if err != nil {
		return apperr.Wrap(op, err)
	}
	lease := activeLeaseByID(curState, leaseID)
	if lease == nil {
		return apperr.Newf(op, "active lease not found: %s", leaseID)
	}
	lease.ExpiresAt = time.Now().UTC().Add(ttl)
	if m.leases != nil {
		if err := m.leases.RenewLease(ctx, m.scopeID, lease.ID, lease.Owner, lease.EpochID, lease.FencingToken, lease.ExpiresAt); err != nil {
			return apperr.Wrap(op, err)
		}
	}
	if lease.Action == "rollback" {
		curState.ActiveRollbackLease = lease
	} else {
		curState.ActiveLease = lease
	}
	return m.store.Save(curState)
}

func activeLeaseByID(state models.RuntimeState, leaseID string) *models.Lease {
	if state.ActiveLease != nil && state.ActiveLease.ID == leaseID {
		return state.ActiveLease
	}
	if state.ActiveRollbackLease != nil && state.ActiveRollbackLease.ID == leaseID {
		return state.ActiveRollbackLease
	}
	return nil
}
