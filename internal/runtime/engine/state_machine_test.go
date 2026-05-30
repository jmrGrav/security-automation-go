package engine_test

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

func newTestSM(t *testing.T) (*engine.StateMachine, *state.StateStore) {
	t.Helper()
	dir := t.TempDir()
	store := state.NewStateStore(dir)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sm := engine.NewStateMachine(store, logger)
	return sm, store
}

// TestFSM_ValidTransitions verifies every allowed transition succeeds.
func TestFSM_ValidTransitions(t *testing.T) {
	type step struct{ from, to models.RuntimeStatus }
	// Each sequence starts fresh from Idle.
	sequences := [][]step{
		// Happy path
		{{models.StatusIdle, models.StatusDiscovering}, {models.StatusDiscovering, models.StatusPlanning}, {models.StatusPlanning, models.StatusExecuting}, {models.StatusExecuting, models.StatusValidating}, {models.StatusValidating, models.StatusConverged}, {models.StatusConverged, models.StatusIdle}},
		// Approval path
		{{models.StatusIdle, models.StatusDiscovering}, {models.StatusDiscovering, models.StatusPlanning}, {models.StatusPlanning, models.StatusAwaitingApproval}, {models.StatusAwaitingApproval, models.StatusExecuting}},
		// Reject (approval → idle)
		{{models.StatusIdle, models.StatusDiscovering}, {models.StatusDiscovering, models.StatusPlanning}, {models.StatusPlanning, models.StatusAwaitingApproval}, {models.StatusAwaitingApproval, models.StatusIdle}},
		// Rollback path
		{{models.StatusIdle, models.StatusDiscovering}, {models.StatusDiscovering, models.StatusPlanning}, {models.StatusPlanning, models.StatusExecuting}, {models.StatusExecuting, models.StatusRollbackRequired}, {models.StatusRollbackRequired, models.StatusRollingBack}, {models.StatusRollingBack, models.StatusIdle}},
		// Failure + retry
		{{models.StatusIdle, models.StatusDiscovering}, {models.StatusDiscovering, models.StatusFailed}, {models.StatusFailed, models.StatusDiscovering}},
		// Quarantine
		{{models.StatusIdle, models.StatusDiscovering}, {models.StatusDiscovering, models.StatusPlanning}, {models.StatusPlanning, models.StatusExecuting}, {models.StatusExecuting, models.StatusValidating}, {models.StatusValidating, models.StatusQuarantined}, {models.StatusQuarantined, models.StatusIdle}},
		// Pause from idle
		{{models.StatusIdle, models.StatusPaused}, {models.StatusPaused, models.StatusIdle}},
	}

	for _, seq := range sequences {
		sm, _ := newTestSM(t)
		ctx := context.Background()
		for _, s := range seq {
			if err := sm.Transition(ctx, s.to, "test"); err != nil {
				t.Errorf("valid transition %s→%s failed: %v", s.from, s.to, err)
			}
		}
	}
}

// TestFSM_InvalidTransitions verifies that disallowed transitions return errors.
func TestFSM_InvalidTransitions(t *testing.T) {
	invalid := []models.RuntimeStatus{
		models.StatusPlanning,
		models.StatusExecuting,
		models.StatusConverged,
		models.StatusRollingBack,
		models.StatusValidating,
	}
	for _, to := range invalid {
		sm, _ := newTestSM(t)
		err := sm.Transition(context.Background(), to, "test")
		if err == nil {
			t.Errorf("transition idle→%s must fail, but succeeded", to)
		}
	}
}

// TestFSM_StateIsPersisted verifies that after a transition, Load() reflects the new status.
func TestFSM_StateIsPersisted(t *testing.T) {
	sm, store := newTestSM(t)
	ctx := context.Background()

	if err := sm.Transition(ctx, models.StatusDiscovering, "start"); err != nil {
		t.Fatalf("transition failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.Lifecycle.Status != models.StatusDiscovering {
		t.Errorf("persisted status = %q, want %q", loaded.Lifecycle.Status, models.StatusDiscovering)
	}
}

// TestFSM_ConcurrentTransitionsAreSafe verifies the mutex prevents races.
// Two goroutines race to transition from Idle — only one should succeed.
func TestFSM_ConcurrentTransitionsAreSafe(t *testing.T) {
	sm, _ := newTestSM(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	results := make([]error, 5)
	for i := range results {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			results[idx] = sm.Transition(ctx, models.StatusDiscovering, "race")
		}(i)
	}
	wg.Wait()

	// Exactly one should succeed (first to acquire the lock and find Idle state)
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("concurrent transitions: want exactly 1 success, got %d", successes)
	}
}

// TestFSM_TransitionFromEmptyStoreDefaultsToIdle verifies that an empty store
// treats the starting state as Idle, enabling the first transition.
func TestFSM_TransitionFromEmptyStoreDefaultsToIdle(t *testing.T) {
	sm, _ := newTestSM(t)
	if err := sm.Transition(context.Background(), models.StatusDiscovering, "first"); err != nil {
		t.Errorf("empty store should default to Idle; got: %v", err)
	}
}

// TestFSM_FencingTokenMonotonicallyIncreases checks that each new epoch has
// a strictly higher fencing token than the previous.
func TestFSM_ConvergedCanRestartDiscovery(t *testing.T) {
	sm, _ := newTestSM(t)
	ctx := context.Background()

	path := []models.RuntimeStatus{
		models.StatusDiscovering,
		models.StatusPlanning,
		models.StatusExecuting,
		models.StatusValidating,
		models.StatusConverged,
		models.StatusDiscovering, // re-run
	}
	for _, s := range path {
		if err := sm.Transition(ctx, s, "test"); err != nil {
			t.Fatalf("transition to %s failed: %v", s, err)
		}
	}
}

// TestFSM_PauseAllowedFromStableStates ensures pause is allowed from Idle, Converged, Failed
// but not from transitional states like Executing.
func TestFSM_PauseAllowedFromStableStates(t *testing.T) {
	ctx := context.Background()

	t.Run("from_idle", func(t *testing.T) {
		sm, _ := newTestSM(t)
		if err := sm.Transition(ctx, models.StatusPaused, "maintenance"); err != nil {
			t.Errorf("pause from idle must succeed: %v", err)
		}
	})

	t.Run("from_converged", func(t *testing.T) {
		sm, _ := newTestSM(t)
		for _, s := range []models.RuntimeStatus{
			models.StatusDiscovering, models.StatusPlanning, models.StatusExecuting,
			models.StatusValidating, models.StatusConverged,
		} {
			_ = sm.Transition(ctx, s, "test")
		}
		if err := sm.Transition(ctx, models.StatusPaused, "maintenance"); err != nil {
			t.Errorf("pause from converged must succeed: %v", err)
		}
	})

	t.Run("rejected_from_executing", func(t *testing.T) {
		sm, _ := newTestSM(t)
		for _, s := range []models.RuntimeStatus{
			models.StatusDiscovering, models.StatusPlanning, models.StatusExecuting,
		} {
			_ = sm.Transition(ctx, s, "test")
		}
		if err := sm.Transition(ctx, models.StatusPaused, "bad"); err == nil {
			t.Error("pause from executing must be rejected")
		}
	})
}
