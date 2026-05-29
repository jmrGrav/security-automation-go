package recovery

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/checkpoint"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

type noOpIntegrity struct{}

func (noOpIntegrity) IntegrityCheck(context.Context) error { return nil }

type scopedLeaseStore struct {
	leases map[string]*models.Lease
}

func (s scopedLeaseStore) GetActiveLease(_ context.Context, scopeID string, action string) (*models.Lease, error) {
	return s.leases[scopeID+":"+action], nil
}

type fakeOwnershipStore struct {
	claims  []ownership.OwnershipClaim
	lineage map[string][]ownership.LineageEvent
}

func (f fakeOwnershipStore) ListClaims(_ context.Context) ([]ownership.OwnershipClaim, error) {
	return f.claims, nil
}

func (f fakeOwnershipStore) ListLineage(_ context.Context, scopeID string, resourceID string, limit int) ([]ownership.LineageEvent, error) {
	key := scopeID + "|" + resourceID
	events := f.lineage[key]
	if len(events) == 0 {
		return nil, nil
	}
	if limit > 0 && len(events) > limit {
		return events[:limit], nil
	}
	return events, nil
}

func TestEventEngineRecoverFromCheckpointAndEvents(t *testing.T) {
	tmpDir := t.TempDir()
	stateStore := state.NewStateStore(tmpDir)
	mem := &memoryEventStore{lastSeq: 3}
	cpMgr := checkpoint.NewManager(mem, mem, nil, 5)

	baseState := models.RuntimeState{
		LastRunID: "run-1",
		Lifecycle: models.LifecycleState{
			Status:        models.StatusPlanning,
			LastUpdatedAt: time.Now().UTC(),
		},
	}
	event := events.Event{
		ID:            1,
		Sequence:      1,
		ScopeID:       "scope-a",
		Category:      events.CategoryLifecycle,
		Type:          events.TypeLifecycleTransition,
		CorrelationID: "corr-1",
		Timestamp:     time.Now().UTC(),
	}
	if _, err := cpMgr.SaveRuntimeState(context.Background(), "scope-a", "transition:planning", event, baseState); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}
	mem.events = append(mem.events,
		events.Event{
			ID:        2,
			Sequence:  2,
			ScopeID:   "scope-a",
			Category:  events.CategoryLifecycle,
			Type:      events.TypeLifecycleTransition,
			Timestamp: time.Now().UTC(),
			Payload:   []byte(`{"from":"planning","to":"executing","reason":"go"}`),
		},
		events.Event{
			ID:        3,
			Sequence:  3,
			ScopeID:   "scope-a",
			Category:  events.CategoryLifecycle,
			Type:      events.TypeLifecycleTransition,
			Timestamp: time.Now().UTC(),
			Payload:   []byte(`{"from":"executing","to":"converged","reason":"done"}`),
		},
	)

	engine := NewEventEngine(cpMgr, mem, stateStore, nil, noOpIntegrity{})
	report, err := engine.Recover(context.Background(), RecoveryOptions{
		ScopeID: "scope-a",
	})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !report.UsedCheckpoint || report.FinalSequence != 3 || report.EventsApplied != 2 {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.RecoveredState.Lifecycle.Status != models.StatusConverged {
		t.Fatalf("expected converged state, got %s", report.RecoveredState.Lifecycle.Status)
	}
}

func TestEventEngineRecoveryIsScopeAwareForLeases(t *testing.T) {
	tmpDir := t.TempDir()
	stateStore := state.NewStateStore(tmpDir)
	mem := &memoryEventStore{}
	cpMgr := checkpoint.NewManager(mem, mem, nil, 5)

	now := time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC)
	if _, err := cpMgr.SaveRuntimeState(context.Background(), "scope-a", "test", events.Event{
		ID:        1,
		Sequence:  1,
		ScopeID:   "scope-a",
		Timestamp: now,
	}, models.RuntimeState{
		Lifecycle: models.LifecycleState{Status: models.StatusIdle, LastUpdatedAt: now},
	}); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}
	mem.lastSeq = 1

	engine := NewEventEngine(cpMgr, mem, stateStore, scopedLeaseStore{
		leases: map[string]*models.Lease{
			"scope-b:reconcile": {ID: "lease-other", Action: "reconcile"},
		},
	}, noOpIntegrity{})

	report, err := engine.Recover(context.Background(), RecoveryOptions{ScopeID: "scope-a", DryRun: true})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if report.OrphanLeaseDetected {
		t.Fatal("expected scoped lease detection to ignore other scopes")
	}
}

func TestEventEngineRecoveryDetectsScopedOrphanLease(t *testing.T) {
	tmpDir := t.TempDir()
	stateStore := state.NewStateStore(tmpDir)
	mem := &memoryEventStore{lastSeq: 1}
	cpMgr := checkpoint.NewManager(mem, mem, nil, 5)
	now := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	if _, err := cpMgr.SaveRuntimeState(context.Background(), "scope-a", "test", events.Event{
		ID:        1,
		Sequence:  1,
		ScopeID:   "scope-a",
		Timestamp: now,
	}, models.RuntimeState{
		Lifecycle: models.LifecycleState{Status: models.StatusIdle, LastUpdatedAt: now},
	}); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	engine := NewEventEngine(cpMgr, mem, stateStore, scopedLeaseStore{
		leases: map[string]*models.Lease{
			"scope-a:reconcile": {ID: "lease-a", Action: "reconcile"},
		},
	}, noOpIntegrity{})
	report, err := engine.Recover(context.Background(), RecoveryOptions{ScopeID: "scope-a", DryRun: true})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !report.OrphanLeaseDetected {
		t.Fatal("expected scoped orphan lease detection")
	}
}

func TestEventEngineRecoveryDetectsZombieEpoch(t *testing.T) {
	tmpDir := t.TempDir()
	stateStore := state.NewStateStore(tmpDir)
	mem := &memoryEventStore{lastSeq: 1}
	cpMgr := checkpoint.NewManager(mem, mem, nil, 5)
	now := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	if _, err := cpMgr.SaveRuntimeState(context.Background(), "scope-a", "test", events.Event{
		ID:        1,
		Sequence:  1,
		ScopeID:   "scope-a",
		Timestamp: now,
	}, models.RuntimeState{
		Lifecycle: models.LifecycleState{Status: models.StatusExecuting, LastUpdatedAt: now},
		CurrentEpoch: models.Epoch{
			ID:         "epoch-1",
			Generation: 3,
			CreatedAt:  now,
		},
	}); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	engine := NewEventEngine(cpMgr, mem, stateStore, scopedLeaseStore{}, noOpIntegrity{})
	report, err := engine.Recover(context.Background(), RecoveryOptions{ScopeID: "scope-a", DryRun: true})
	if err != nil {
		t.Fatalf("recover: %v", err)
	}
	if !report.ZombieEpochDetected {
		t.Fatal("expected zombie epoch detection")
	}
}

func TestEventEngineRecoveryDetectsOwnershipInvariantViolation(t *testing.T) {
	tmpDir := t.TempDir()
	stateStore := state.NewStateStore(tmpDir)
	mem := &memoryEventStore{lastSeq: 1}
	cpMgr := checkpoint.NewManager(mem, mem, nil, 5)
	now := time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC)
	if _, err := cpMgr.SaveRuntimeState(context.Background(), "scope-a", "test", events.Event{
		ID:        1,
		Sequence:  1,
		ScopeID:   "scope-a",
		Timestamp: now,
	}, models.RuntimeState{
		Lifecycle: models.LifecycleState{Status: models.StatusIdle, LastUpdatedAt: now},
	}); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	engine := NewEventEngine(cpMgr, mem, stateStore, scopedLeaseStore{}, noOpIntegrity{})
	engine.SetOwnershipStore(fakeOwnershipStore{
		claims: []ownership.OwnershipClaim{
			{ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync", Epoch: 3, Timestamp: now},
		},
		lineage: map[string][]ownership.LineageEvent{
			"scope-a|res-1": {
				{
					ID:         "l-1",
					ScopeID:    "scope-a",
					ResourceID: "res-1",
					DomainID:   "dashboard",
					EventType:  ownership.LineageEventClaim,
					Epoch:      2,
					CreatedAt:  now,
				},
			},
		},
	})

	report, err := engine.Recover(context.Background(), RecoveryOptions{ScopeID: "scope-a", DryRun: true})
	if err == nil {
		t.Fatal("expected recovery error on ownership invariant violation")
	}
	if !report.OwnershipInvariantViolation {
		t.Fatal("expected ownership invariant violation")
	}
	if len(report.OwnershipInvariantIssues) == 0 {
		t.Fatal("expected ownership invariant issues")
	}
}

func TestEventEngineRecoveryOwnershipDivergenceIsScopeAware(t *testing.T) {
	tmpDir := t.TempDir()
	stateStore := state.NewStateStore(tmpDir)
	mem := &memoryEventStore{lastSeq: 1}
	cpMgr := checkpoint.NewManager(mem, mem, nil, 5)
	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)

	saveScope := func(scopeID string) {
		if _, err := cpMgr.SaveRuntimeState(context.Background(), scopeID, "test", events.Event{
			ID:        1,
			Sequence:  1,
			ScopeID:   scopeID,
			Timestamp: now,
		}, models.RuntimeState{
			Lifecycle: models.LifecycleState{Status: models.StatusIdle, LastUpdatedAt: now},
		}); err != nil {
			t.Fatalf("save checkpoint(%s): %v", scopeID, err)
		}
	}
	saveScope("scope-a")
	saveScope("scope-b")

	engine := NewEventEngine(cpMgr, mem, stateStore, scopedLeaseStore{}, noOpIntegrity{})
	engine.SetOwnershipStore(fakeOwnershipStore{
		claims: []ownership.OwnershipClaim{
			{ScopeID: "scope-a", ResourceID: "res-ok", DomainID: "cf-sync", Epoch: 2, Timestamp: now},
			{ScopeID: "scope-b", ResourceID: "res-bad", DomainID: "cf-sync", Epoch: 3, Timestamp: now},
		},
		lineage: map[string][]ownership.LineageEvent{
			"scope-a|res-ok": {
				{ID: "ok-1", ScopeID: "scope-a", ResourceID: "res-ok", DomainID: "cf-sync", EventType: ownership.LineageEventClaim, Epoch: 2, CreatedAt: now},
			},
			"scope-b|res-bad": {
				{ID: "bad-1", ScopeID: "scope-b", ResourceID: "res-bad", DomainID: "dashboard", EventType: ownership.LineageEventClaim, Epoch: 2, CreatedAt: now},
			},
		},
	})

	reportA, errA := engine.Recover(context.Background(), RecoveryOptions{ScopeID: "scope-a", DryRun: true})
	if errA != nil {
		t.Fatalf("scope-a recover should succeed, got %v", errA)
	}
	if reportA.OwnershipInvariantViolation {
		t.Fatalf("scope-a should have no ownership invariant violation: %+v", reportA.OwnershipInvariantIssues)
	}

	reportB, errB := engine.Recover(context.Background(), RecoveryOptions{ScopeID: "scope-b", DryRun: true})
	if errB == nil {
		t.Fatal("scope-b recover should fail on ownership divergence")
	}
	if !reportB.OwnershipInvariantViolation {
		t.Fatal("scope-b should flag ownership invariant violation")
	}
}

func TestEventEngineRecoveryOwnershipDivergenceDeterministicAfterRestart(t *testing.T) {
	tmpDir := t.TempDir()
	stateStore := state.NewStateStore(tmpDir)
	mem := &memoryEventStore{lastSeq: 1}
	cpMgr := checkpoint.NewManager(mem, mem, nil, 5)
	now := time.Date(2026, 5, 29, 1, 0, 0, 0, time.UTC)
	if _, err := cpMgr.SaveRuntimeState(context.Background(), "scope-z", "test", events.Event{
		ID:        1,
		Sequence:  1,
		ScopeID:   "scope-z",
		Timestamp: now,
	}, models.RuntimeState{
		Lifecycle: models.LifecycleState{Status: models.StatusIdle, LastUpdatedAt: now},
	}); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	store := fakeOwnershipStore{
		claims: []ownership.OwnershipClaim{
			{ScopeID: "scope-z", ResourceID: "res-z", DomainID: "cf-sync", Epoch: 4, Timestamp: now},
		},
		lineage: map[string][]ownership.LineageEvent{
			"scope-z|res-z": {
				{ID: "z-1", ScopeID: "scope-z", ResourceID: "res-z", DomainID: "cf-sync", EventType: ownership.LineageEventClaim, Epoch: 3, CreatedAt: now},
			},
		},
	}

	engine1 := NewEventEngine(cpMgr, mem, stateStore, scopedLeaseStore{}, noOpIntegrity{})
	engine1.SetOwnershipStore(store)
	report1, err1 := engine1.Recover(context.Background(), RecoveryOptions{ScopeID: "scope-z", DryRun: true})
	if err1 == nil || !report1.OwnershipInvariantViolation {
		t.Fatalf("first run must detect ownership divergence, report=%+v err=%v", report1, err1)
	}

	// Restart semantics: new engine with same durable inputs should produce same violation class.
	engine2 := NewEventEngine(cpMgr, mem, stateStore, scopedLeaseStore{}, noOpIntegrity{})
	engine2.SetOwnershipStore(store)
	report2, err2 := engine2.Recover(context.Background(), RecoveryOptions{ScopeID: "scope-z", DryRun: true})
	if err2 == nil || !report2.OwnershipInvariantViolation {
		t.Fatalf("second run must detect ownership divergence, report=%+v err=%v", report2, err2)
	}
	if len(report1.OwnershipInvariantIssues) == 0 || len(report2.OwnershipInvariantIssues) == 0 {
		t.Fatal("expected invariant issue details on both runs")
	}
	if report1.OwnershipInvariantIssues[0] != report2.OwnershipInvariantIssues[0] {
		t.Fatalf("expected deterministic divergence signature, got %v vs %v", report1.OwnershipInvariantIssues, report2.OwnershipInvariantIssues)
	}
}

type memoryEventStore struct {
	events      []events.Event
	checkpoints []events.Checkpoint
	lastSeq     uint64
}

func (m *memoryEventStore) Append(context.Context, *events.Event) error { return nil }
func (m *memoryEventStore) List(_ context.Context, scopeID string, afterSequence uint64) ([]events.Event, error) {
	var out []events.Event
	for _, event := range m.events {
		if event.ScopeID == scopeID && event.Sequence > afterSequence {
			out = append(out, event)
		}
	}
	return out, nil
}
func (m *memoryEventStore) GetLastSequence(_ context.Context, _ string) (uint64, error) {
	return m.lastSeq, nil
}
func (m *memoryEventStore) SaveCheckpoint(_ context.Context, checkpoint events.Checkpoint) error {
	m.checkpoints = append(m.checkpoints, checkpoint)
	return nil
}
func (m *memoryEventStore) LatestCheckpoint(_ context.Context, scopeID string, name string) (events.Checkpoint, error) {
	for i := len(m.checkpoints) - 1; i >= 0; i-- {
		cp := m.checkpoints[i]
		if cp.ScopeID == scopeID && cp.Name == name {
			return cp, nil
		}
	}
	return events.Checkpoint{}, events.ErrCheckpointNotFound
}
func (m *memoryEventStore) ListCheckpoints(_ context.Context, scopeID string, name string, limit int) ([]events.Checkpoint, error) {
	var out []events.Checkpoint
	for i := len(m.checkpoints) - 1; i >= 0; i-- {
		cp := m.checkpoints[i]
		if cp.ScopeID == scopeID && cp.Name == name {
			out = append(out, cp)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}
func (m *memoryEventStore) DeleteCheckpoint(_ context.Context, scopeID string, name string, sequence uint64) error {
	var kept []events.Checkpoint
	for _, cp := range m.checkpoints {
		if cp.ScopeID == scopeID && cp.Name == name && cp.Sequence == sequence {
			continue
		}
		kept = append(kept, cp)
	}
	m.checkpoints = kept
	return nil
}
