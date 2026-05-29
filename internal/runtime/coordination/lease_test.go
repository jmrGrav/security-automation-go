package coordination

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestLeaseManager_Acquire_Success(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	lm := NewLeaseManager(store, time.Minute)

	ctx := context.Background()
	lease, epoch, err := lm.Acquire(ctx, "owner1", "reconcile", "run1")
	if err != nil {
		t.Fatalf("failed to acquire lease: %v", err)
	}

	if lease.Owner != "owner1" {
		t.Errorf("expected owner1, got %s", lease.Owner)
	}
	if epoch.Generation != 1 {
		t.Errorf("expected generation 1, got %d", epoch.Generation)
	}

	// Verify persistence
	curState, _ := store.Load()
	if curState.ActiveLease == nil || curState.ActiveLease.ID != lease.ID {
		t.Error("lease was not persisted correctly")
	}
}

func TestLeaseManager_Acquire_Overlap(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	lm := NewLeaseManager(store, time.Minute)

	ctx := context.Background()
	_, _, _ = lm.Acquire(ctx, "owner1", "reconcile", "run1")

	// Attempt acquisition by another owner
	_, _, err := lm.Acquire(ctx, "owner2", "reconcile", "run2")
	if err == nil {
		t.Error("expected error for overlapping lease acquisition, got nil")
	}
}

func TestLeaseManager_Acquire_Expired(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	// Very short expiry for test
	lm := NewLeaseManager(store, -time.Second)

	ctx := context.Background()
	_, _, _ = lm.Acquire(ctx, "owner1", "reconcile", "run1")

	// Even though owner1 had it, it's expired, so owner2 can take it
	lease, epoch, err := lm.Acquire(ctx, "owner2", "reconcile", "run2")
	if err != nil {
		t.Fatalf("failed to acquire expired lease: %v", err)
	}

	if lease.Owner != "owner2" {
		t.Errorf("expected owner2 to take over, got %s", lease.Owner)
	}
	if epoch.Generation != 2 {
		t.Errorf("expected generation 2, got %d", epoch.Generation)
	}
}

func TestLeaseManager_Release(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	lm := NewLeaseManager(store, time.Minute)

	ctx := context.Background()
	lease, _, _ := lm.Acquire(ctx, "owner1", "reconcile", "run1")

	err := lm.Release(ctx, lease.ID)
	if err != nil {
		t.Fatalf("failed to release lease: %v", err)
	}

	curState, _ := store.Load()
	if curState.ActiveLease != nil {
		t.Error("lease was not cleared after release")
	}
}

func TestLeaseManagerUsesPersistentLeaseStore(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	db, err := sqlite.New(tmpDir)
	if err != nil {
		t.Fatalf("new sqlite: %v", err)
	}
	defer db.Close()

	repo := sqlite.NewLeaseRepository(db)
	lm := NewLeaseManager(store, time.Minute).WithLeaseStore("scope-a", repo)

	ctx := context.Background()
	lease, _, err := lm.Acquire(ctx, "owner1", "reconcile", "run1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	persisted, err := repo.GetActiveLease(ctx, "scope-a", "reconcile")
	if err != nil {
		t.Fatalf("get persisted lease: %v", err)
	}
	if persisted == nil || persisted.ID != lease.ID {
		t.Fatalf("expected persistent lease %s, got %+v", lease.ID, persisted)
	}

	if _, _, err := lm.Acquire(ctx, "owner2", "reconcile", "run2"); err == nil {
		t.Fatal("expected persistent active lease to block another owner")
	}
	if err := lm.Release(ctx, lease.ID); err != nil {
		t.Fatalf("release: %v", err)
	}
	persisted, err = repo.GetActiveLease(ctx, "scope-a", "reconcile")
	if err != nil {
		t.Fatalf("get after release: %v", err)
	}
	if persisted != nil {
		t.Fatalf("expected persistent lease to be released, got %+v", persisted)
	}
}

func TestLeaseHeartbeatRenewsAndStopsOnCancel(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	db, err := sqlite.New(tmpDir)
	if err != nil {
		t.Fatalf("new sqlite: %v", err)
	}
	defer db.Close()

	repo := sqlite.NewLeaseRepository(db)
	lm := NewLeaseManager(store, 50*time.Millisecond).WithLeaseStore("scope-a", repo)
	lease, _, err := lm.Acquire(context.Background(), "owner1", "reconcile", "run1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	initial := lease.ExpiresAt

	ctx, cancel := context.WithCancel(context.Background())
	handle := lm.StartHeartbeat(ctx, *lease, HeartbeatConfig{Interval: 5 * time.Millisecond, TTL: 2 * time.Second, FailureThreshold: 2})
	deadline := time.After(time.Second)
	for {
		renewed, err := repo.GetActiveLease(context.Background(), "scope-a", "reconcile")
		if err != nil {
			t.Fatalf("get renewed lease: %v", err)
		}
		if renewed != nil && renewed.ExpiresAt.After(initial.Add(time.Second)) {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("expected heartbeat to renew lease beyond %s, got %+v", initial, renewed)
		case <-time.After(5 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-handle.Done():
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not stop after cancel")
	}
}

func TestLeaseHeartbeatReportsLostLeaseOnRenewFailure(t *testing.T) {
	store := state.NewStateStore(t.TempDir())
	failing := &failingLeaseStore{err: errors.New("renew failed")}
	lm := NewLeaseManager(store, 50*time.Millisecond).WithLeaseStore("scope-a", failing)
	lease, _, err := lm.Acquire(context.Background(), "owner1", "reconcile", "run1")
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}

	handle := lm.StartHeartbeat(context.Background(), *lease, HeartbeatConfig{Interval: time.Millisecond, TTL: 10 * time.Millisecond, FailureThreshold: 1})
	select {
	case err := <-handle.Lost():
		if err == nil {
			t.Fatal("expected lost lease error")
		}
	case <-time.After(time.Second):
		t.Fatal("expected lost lease signal")
	}
	select {
	case <-handle.Done():
	case <-time.After(time.Second):
		t.Fatal("heartbeat did not stop after lost lease")
	}
}

type failingLeaseStore struct {
	mu     sync.Mutex
	leases map[string]*models.Lease
	err    error
}

func (s *failingLeaseStore) GetActiveLease(_ context.Context, _ string, action string) (*models.Lease, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.leases == nil {
		return nil, nil
	}
	lease := s.leases[action]
	if lease == nil || lease.IsExpired() {
		return nil, nil
	}
	copy := *lease
	return &copy, nil
}

func (s *failingLeaseStore) AcquireLease(_ context.Context, _ string, lease models.Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.leases == nil {
		s.leases = make(map[string]*models.Lease)
	}
	copy := lease
	s.leases[lease.Action] = &copy
	return nil
}

func (s *failingLeaseStore) RenewLease(context.Context, string, string, string, string, int64, time.Time) error {
	return s.err
}

func (s *failingLeaseStore) ReleaseLease(_ context.Context, _ string, leaseID string, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for action, lease := range s.leases {
		if lease.ID == leaseID && lease.Owner == owner {
			delete(s.leases, action)
		}
	}
	return nil
}
