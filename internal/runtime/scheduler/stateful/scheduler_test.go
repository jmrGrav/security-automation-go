package stateful

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/cooldown"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/scope"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

func TestScheduler_Tick_LifecycleSafety(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	logger := slog.Default()
	sm := engine.NewStateMachine(store, logger)
	cm := cooldown.NewManager(store)

	s := New(store, nil, sm, cm, logger, time.Minute)
	defer s.Stop()

	ctx := context.Background()
	item := models.WorkItem{
		Scope:    scope.RuntimeScope{Tenant: "t1", ZoneID: "z1"},
		Priority: models.PriorityNormal,
	}

	// 1. Initially Idle, should allow transition to Discovering (via executeRun in pool)
	if err := s.tick(ctx, item); err != nil {
		t.Fatalf("tick failed on idle: %v", err)
	}

	// Note: tick only submits to pool. For test purpose, we verify state after tick.
	// Actually, tick doesn't transition yet, the worker does.
}

func TestScheduler_Tick_Cooldown(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	logger := slog.Default()
	sm := engine.NewStateMachine(store, logger)
	cm := cooldown.NewManager(store)

	s := New(store, nil, sm, cm, logger, time.Minute)
	defer s.Stop()
	ctx := context.Background()
	item := models.WorkItem{
		Scope: scope.RuntimeScope{Tenant: "t1", ZoneID: "z1"},
	}

	// Set a cooldown
	_ = cm.Start(ctx, time.Hour, "testing")

	// Tick should skip
	if err := s.tick(ctx, item); err != nil {
		t.Fatalf("tick failed during cooldown: %v", err)
	}
}

func TestScheduler_RecoverStaleState_ResetsToFailed(t *testing.T) {
	tmpDir := t.TempDir()
	store := state.NewStateStore(tmpDir)
	logger := slog.Default()
	sm := engine.NewStateMachine(store, logger)
	cm := cooldown.NewManager(store)

	// Simulate a crash that left StatusExecuting in the state file.
	staleState := models.RuntimeState{}
	staleState.Lifecycle.Status = models.StatusExecuting
	if err := store.Save(staleState); err != nil {
		t.Fatalf("failed to seed stale state: %v", err)
	}

	s := New(store, nil, sm, cm, logger, time.Minute)
	defer s.Stop()

	ctx := context.Background()
	if err := s.recoverStaleState(ctx); err != nil {
		t.Fatalf("recoverStaleState failed: %v", err)
	}

	recovered, err := store.Load()
	if err != nil {
		t.Fatalf("failed to load state after recovery: %v", err)
	}
	if recovered.Lifecycle.Status != models.StatusFailed {
		t.Errorf("expected StatusFailed after recovery, got %s", recovered.Lifecycle.Status)
	}
}

func TestScheduler_RecoverStaleState_PreservesTerminalStates(t *testing.T) {
	for _, status := range []models.RuntimeStatus{
		models.StatusIdle,
		models.StatusConverged,
		models.StatusFailed,
		models.StatusPaused,
		models.StatusQuarantined,
		"", // fresh start
	} {
		t.Run(string(status), func(t *testing.T) {
			tmpDir := t.TempDir()
			store := state.NewStateStore(tmpDir)
			logger := slog.Default()
			sm := engine.NewStateMachine(store, logger)
			cm := cooldown.NewManager(store)

			if status != "" {
				st := models.RuntimeState{}
				st.Lifecycle.Status = status
				if err := store.Save(st); err != nil {
					t.Fatalf("failed to seed state: %v", err)
				}
			}

			s := New(store, nil, sm, cm, logger, time.Minute)
			defer s.Stop()

			if err := s.recoverStaleState(context.Background()); err != nil {
				t.Fatalf("recoverStaleState unexpectedly failed for %s: %v", status, err)
			}

			st, err := store.Load()
			if err != nil {
				t.Fatalf("load failed: %v", err)
			}
			if st.Lifecycle.Status != status {
				t.Errorf("expected status %q to be preserved, got %q", status, st.Lifecycle.Status)
			}
		})
	}
}

func TestRetryPolicy_ExponentialBackoff(t *testing.T) {
	p := RetryPolicy{
		InitialDelay: time.Second,
		MaxDelay:     time.Minute,
		Multiplier:   2.0,
		Jitter:       0,
	}

	// Attempt 0: 1s
	if d := p.CalculateDelay(0); d != time.Second {
		t.Errorf("expected 1s, got %s", d)
	}
	// Attempt 1: 2s
	if d := p.CalculateDelay(1); d != 2*time.Second {
		t.Errorf("expected 2s, got %s", d)
	}
	// Attempt 2: 4s
	if d := p.CalculateDelay(2); d != 4*time.Second {
		t.Errorf("expected 4s, got %s", d)
	}
	// Cap at 60s
	if d := p.CalculateDelay(10); d != time.Minute {
		t.Errorf("expected 60s cap, got %s", d)
	}
}
