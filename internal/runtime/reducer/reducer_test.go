package reducer

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

func TestApplyLifecycleTransitionMatchesReplay(t *testing.T) {
	at := time.Date(2026, 5, 27, 9, 30, 0, 0, time.UTC)
	live := ApplyLifecycleTransition(models.RuntimeState{}, TransitionInput{
		From:         models.StatusIdle,
		To:           models.StatusDiscovering,
		At:           at,
		EpochID:      "epoch-1",
		FencingToken: 7,
		LeaseID:      "lease-1",
	})

	event := events.Event{
		Type:      events.TypeLifecycleTransition,
		Timestamp: at,
		Payload:   []byte(`{"from":"idle","to":"discovering","reason":"start"}`),
		Metadata: map[string]any{
			"epoch_id":      "epoch-1",
			"fencing_token": float64(7),
			"lease_id":      "lease-1",
		},
	}
	replayed, err := ApplyEvent(models.RuntimeState{}, event)
	if err != nil {
		t.Fatalf("apply replay event: %v", err)
	}

	if live.Lifecycle.Status != replayed.Lifecycle.Status ||
		live.ActiveRollbackID != replayed.ActiveRollbackID ||
		live.CurrentEpoch.ID != replayed.CurrentEpoch.ID ||
		live.CurrentEpoch.Generation != replayed.CurrentEpoch.Generation ||
		live.ActiveLease == nil || replayed.ActiveLease == nil ||
		live.ActiveLease.ID != replayed.ActiveLease.ID {
		t.Fatalf("live/replay diverged:\nlive=%+v\nreplay=%+v", live, replayed)
	}
}

func TestApplyLifecycleTransitionClearsTerminalLeases(t *testing.T) {
	state := models.RuntimeState{
		ActiveLease:         &models.Lease{ID: "lease-r", Action: "reconcile"},
		ActiveRollbackLease: &models.Lease{ID: "lease-b", Action: "rollback"},
		ActiveRollbackID:    "epoch-1",
	}

	cleared := ApplyLifecycleTransition(state, TransitionInput{
		From: models.StatusRollingBack,
		To:   models.StatusIdle,
		At:   time.Now().UTC(),
	})

	if cleared.ActiveLease != nil || cleared.ActiveRollbackLease != nil || cleared.ActiveRollbackID != "" {
		t.Fatalf("expected terminal transition to clear leases, got %+v", cleared)
	}
}

func TestApplyLifecycleTransitionUsesRollbackLease(t *testing.T) {
	state := ApplyLifecycleTransition(models.RuntimeState{}, TransitionInput{
		From:         models.StatusRollbackRequired,
		To:           models.StatusRollingBack,
		At:           time.Now().UTC(),
		EpochID:      "rollback-1",
		FencingToken: 11,
		LeaseID:      "lease-rb",
	})

	if state.ActiveRollbackLease == nil || state.ActiveRollbackLease.ID != "lease-rb" {
		t.Fatalf("expected rollback lease to be active, got %+v", state.ActiveRollbackLease)
	}
	if state.ActiveLease != nil {
		t.Fatalf("expected reconcile lease to stay nil during rollback, got %+v", state.ActiveLease)
	}
	if state.ActiveRollbackID != "rollback-1" {
		t.Fatalf("expected rollback id to be set, got %q", state.ActiveRollbackID)
	}
}

func TestApplyEventLeaseAcquiredAndConvergedClearsLease(t *testing.T) {
	now := time.Now().UTC()
	state, err := ApplyEvent(models.RuntimeState{}, events.Event{
		Type:      events.TypeLeaseAcquired,
		Timestamp: now,
		Payload:   []byte(`{"lease_id":"lease-1","action":"reconcile","epoch_id":"epoch-1","owner":"worker-1","fencing_token":5,"expires_at":"2026-05-27T11:00:00Z"}`),
	})
	if err != nil {
		t.Fatalf("apply lease event: %v", err)
	}
	if state.ActiveLease == nil || state.ActiveLease.ID != "lease-1" {
		t.Fatalf("expected active lease, got %+v", state.ActiveLease)
	}

	state, err = ApplyEvent(state, events.Event{
		Type:      events.TypeLifecycleTransition,
		Timestamp: now.Add(time.Minute),
		Payload:   []byte(`{"from":"validating","to":"converged","reason":"done"}`),
	})
	if err != nil {
		t.Fatalf("apply converged event: %v", err)
	}
	if state.ActiveLease != nil {
		t.Fatalf("expected converged state to clear lease, got %+v", state.ActiveLease)
	}
}

func TestApplyEventFencingTokenIssuedUpdatesEpoch(t *testing.T) {
	state, err := ApplyEvent(models.RuntimeState{}, events.Event{
		Type:      events.TypeFencingTokenIssued,
		Timestamp: time.Now().UTC(),
		Payload:   []byte(`{"epoch_id":"epoch-2","fencing_token":9,"reason":"renewed"}`),
	})
	if err != nil {
		t.Fatalf("apply fencing event: %v", err)
	}
	if state.CurrentEpoch.ID != "epoch-2" || state.CurrentEpoch.Generation != 9 {
		t.Fatalf("unexpected epoch after fencing event: %+v", state.CurrentEpoch)
	}
}

func TestApplyEventRollbackCompletedClearsRollbackLeaseAndID(t *testing.T) {
	state := models.RuntimeState{
		ActiveRollbackID:    "rollback-1",
		ActiveRollbackLease: &models.Lease{ID: "lease-rb", Action: "rollback"},
	}
	next, err := ApplyEvent(state, events.Event{
		Type:      events.TypeRollbackCompleted,
		Timestamp: time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("apply rollback completed: %v", err)
	}
	if next.ActiveRollbackID != "" || next.ActiveRollbackLease != nil {
		t.Fatalf("expected rollback completion to clear rollback state, got %+v", next)
	}
}
