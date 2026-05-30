package coordination_test

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

func newTestLeaseManager(t *testing.T) *coordination.LeaseManager {
	t.Helper()
	dir := t.TempDir()
	store := state.NewStateStore(dir)
	_ = slog.New(slog.NewTextHandler(io.Discard, nil)) // suppress lint
	return coordination.NewLeaseManager(store, 5*time.Minute)
}

// TestLeaseManager_AcquireSucceeds verifies a lease can be acquired from clean state.
func TestLeaseManager_AcquireSucceeds(t *testing.T) {
	lm := newTestLeaseManager(t)
	lease, epoch, err := lm.Acquire(context.Background(), "worker-1", "reconcile", "run-1")
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	if lease == nil {
		t.Fatal("lease must not be nil")
	}
	if epoch == nil {
		t.Fatal("epoch must not be nil")
	}
	if lease.Owner != "worker-1" {
		t.Errorf("lease owner = %q, want 'worker-1'", lease.Owner)
	}
	if lease.Action != "reconcile" {
		t.Errorf("lease action = %q, want 'reconcile'", lease.Action)
	}
}

// TestLeaseManager_FencingTokenMonotonicallyIncreases verifies each epoch
// has a strictly higher fencing token than the previous.
func TestLeaseManager_FencingTokenMonotonicallyIncreases(t *testing.T) {
	lm := newTestLeaseManager(t)

	lease1, prev, _ := lm.Acquire(context.Background(), "worker-1", "reconcile", "run-1")

	// Release and re-acquire for a new epoch
	_ = lm.Release(context.Background(), lease1.ID)
	_, next, err := lm.Acquire(context.Background(), "worker-1", "reconcile", "run-2")
	if err != nil {
		t.Fatalf("second Acquire failed: %v", err)
	}

	if next.Generation <= prev.Generation {
		t.Errorf("fencing token must increase: prev=%d, next=%d", prev.Generation, next.Generation)
	}
}

// TestLeaseManager_ConflictRejectedWhenActiveLeaseExists verifies that a different
// owner cannot acquire a lease while one is already held.
func TestLeaseManager_ConflictRejectedWhenActiveLeaseExists(t *testing.T) {
	lm := newTestLeaseManager(t)

	_, _, err := lm.Acquire(context.Background(), "worker-1", "reconcile", "run-1")
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	_, _, err = lm.Acquire(context.Background(), "worker-2", "reconcile", "run-2")
	if err == nil {
		t.Error("second owner must not acquire lease while worker-1 holds it")
	}
}

// TestLeaseManager_SameOwnerCanReacquire verifies idempotent re-acquisition
// by the same owner (lease extension pattern).
func TestLeaseManager_SameOwnerCanReacquire(t *testing.T) {
	lm := newTestLeaseManager(t)

	_, _, err := lm.Acquire(context.Background(), "worker-1", "reconcile", "run-1")
	if err != nil {
		t.Fatalf("first acquire failed: %v", err)
	}

	// Same owner re-acquires — must succeed
	_, _, err = lm.Acquire(context.Background(), "worker-1", "reconcile", "run-1-ext")
	if err != nil {
		t.Errorf("same owner re-acquire must succeed: %v", err)
	}
}

// TestLeaseManager_ReleaseAllowsNewAcquire verifies that releasing a lease
// enables a new owner to acquire it.
func TestLeaseManager_ReleaseAllowsNewAcquire(t *testing.T) {
	lm := newTestLeaseManager(t)

	lease, _, _ := lm.Acquire(context.Background(), "worker-1", "reconcile", "run-1")
	if lease == nil {
		t.Fatal("first acquire must succeed")
	}
	if err := lm.Release(context.Background(), lease.ID); err != nil {
		t.Fatalf("Release failed: %v", err)
	}

	_, _, err := lm.Acquire(context.Background(), "worker-2", "reconcile", "run-2")
	if err != nil {
		t.Errorf("new owner must be able to acquire after release: %v", err)
	}
}

// TestLeaseManager_ExpiredLeaseAllowsReacquire verifies that an expired lease
// can be replaced by a new owner.
func TestLeaseManager_ExpiredLeaseAllowsReacquire(t *testing.T) {
	dir := t.TempDir()
	store := state.NewStateStore(dir)
	// Set a very short expiry so it expires immediately
	lm := coordination.NewLeaseManager(store, 1*time.Nanosecond)

	_, _, _ = lm.Acquire(context.Background(), "worker-1", "reconcile", "run-1")
	time.Sleep(10 * time.Millisecond) // let it expire

	// A different owner should now be able to acquire
	_, _, err := coordination.NewLeaseManager(store, 5*time.Minute).Acquire(
		context.Background(), "worker-2", "reconcile", "run-2",
	)
	if err != nil {
		t.Errorf("expired lease must allow new acquire: %v", err)
	}
}

// TestLeaseManager_HasPersistentLeaseStore_False verifies the default state.
func TestLeaseManager_HasPersistentLeaseStore_False(t *testing.T) {
	lm := newTestLeaseManager(t)
	if lm.HasPersistentLeaseStore() {
		t.Error("fresh LeaseManager must not have persistent lease store until WithLeaseStore is called")
	}
}

// TestLeaseManager_NilSafe verifies nil receiver on HasPersistentLeaseStore doesn't panic.
func TestLeaseManager_NilSafe(t *testing.T) {
	var lm *coordination.LeaseManager
	if lm.HasPersistentLeaseStore() {
		t.Error("nil LeaseManager.HasPersistentLeaseStore must return false")
	}
}

// TestLeaseManager_RollbackActionSeparateFromReconcile verifies rollback leases
// are managed independently from reconcile leases.
func TestLeaseManager_RollbackActionSeparateFromReconcile(t *testing.T) {
	lm := newTestLeaseManager(t)

	_, _, _ = lm.Acquire(context.Background(), "worker-1", "reconcile", "run-1")

	// Rollback by a different owner should succeed independently
	_, _, err := lm.Acquire(context.Background(), "rollback-worker", "rollback", "rb-1")
	if err != nil {
		t.Errorf("rollback lease must be independent from reconcile lease: %v", err)
	}
}
