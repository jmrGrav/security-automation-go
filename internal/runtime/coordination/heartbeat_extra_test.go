package coordination

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

func TestHeartbeatHandleStopIsSafe(t *testing.T) {
	var h HeartbeatHandle
	h.Stop()
}

func TestMinDuration(t *testing.T) {
	if got := minDuration(10*time.Second, 5*time.Second); got != 5*time.Second {
		t.Fatalf("unexpected min duration: %s", got)
	}
	if got := minDuration(0, 3*time.Second); got != 3*time.Second {
		t.Fatalf("unexpected min duration for zero left: %s", got)
	}
}

func TestActiveLeaseByID(t *testing.T) {
	state := models.RuntimeState{
		ActiveLease: &models.Lease{ID: "lease-a"},
		ActiveRollbackLease: &models.Lease{
			ID: "lease-b",
		},
	}
	if got := activeLeaseByID(state, "lease-a"); got == nil || got.ID != "lease-a" {
		t.Fatalf("expected active lease-a, got %+v", got)
	}
	if got := activeLeaseByID(state, "lease-b"); got == nil || got.ID != "lease-b" {
		t.Fatalf("expected rollback lease-b, got %+v", got)
	}
	if got := activeLeaseByID(state, "missing"); got != nil {
		t.Fatalf("expected nil for missing lease, got %+v", got)
	}
}

func TestHeartbeatReportsLostLease(t *testing.T) {
	stateStore := state.NewStateStore(t.TempDir())
	lease := models.Lease{ID: "lease-a", Owner: "worker", Action: "reconcile", EpochID: "epoch", FencingToken: 1}
	if err := stateStore.Save(models.RuntimeState{ActiveLease: &lease}); err != nil {
		t.Fatalf("save state: %v", err)
	}
	store := &renewThenFailLeaseStore{failAfter: 1, err: errors.New("renew failed")}
	lm := NewLeaseManager(stateStore, time.Millisecond).WithLeaseStore("scope-a", store)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var lostErr error
	h := lm.StartHeartbeat(ctx, lease, HeartbeatConfig{
		Interval:         time.Millisecond,
		TTL:              time.Millisecond,
		FailureThreshold: 1,
		OnLost: func(err error) {
			lostErr = err
		},
	})
	select {
	case <-h.Lost():
	case <-time.After(time.Second):
		t.Fatal("expected lost lease signal")
	}
	if lostErr == nil {
		t.Fatal("expected OnLost callback to capture renew failure")
	}
	if got := store.renewCalls(); got < 2 {
		t.Fatalf("expected at least one successful renew before loss, got %d renew calls", got)
	}
}

type renewThenFailLeaseStore struct {
	mu        sync.Mutex
	leases    map[string]*models.Lease
	failAfter int
	err       error
	renewCnt  int
}

func (s *renewThenFailLeaseStore) GetActiveLease(_ context.Context, _ string, action string) (*models.Lease, error) {
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

func (s *renewThenFailLeaseStore) AcquireLease(_ context.Context, _ string, lease models.Lease) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.leases == nil {
		s.leases = make(map[string]*models.Lease)
	}
	copy := lease
	s.leases[lease.Action] = &copy
	return nil
}

func (s *renewThenFailLeaseStore) RenewLease(context.Context, string, string, string, string, int64, time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.renewCnt++
	if s.renewCnt > s.failAfter {
		return s.err
	}
	return nil
}

func (s *renewThenFailLeaseStore) ReleaseLease(_ context.Context, _ string, leaseID string, owner string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for action, lease := range s.leases {
		if lease.ID == leaseID && lease.Owner == owner {
			delete(s.leases, action)
		}
	}
	return nil
}

func (s *renewThenFailLeaseStore) renewCalls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.renewCnt
}
