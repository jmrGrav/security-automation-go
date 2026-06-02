package executor

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/execution"
	rollbackmodels "github.com/jm/security-automation-go/internal/rollback/models"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	runmodels "github.com/jm/security-automation-go/internal/runtime/models"
)

type spyRollbackMutator struct {
	calls int
}

func (m *spyRollbackMutator) Execute(execution.MutationOperation) (string, error) {
	m.calls++
	return "ok", nil
}

func (m *spyRollbackMutator) DryRun(execution.MutationOperation) string { return "dry-run" }

type memoryRollbackJournal struct {
	events []runmodels.AuditEvent
}

func (m *memoryRollbackJournal) Append(event runmodels.AuditEvent) error {
	m.events = append(m.events, event)
	return nil
}

func (m *memoryRollbackJournal) List() ([]runmodels.AuditEvent, error) {
	out := make([]runmodels.AuditEvent, len(m.events))
	copy(out, m.events)
	return out, nil
}

type alwaysFailFencing struct{}

func (alwaysFailFencing) ValidateMutation(context.Context, execution.MutationOperation) error {
	return errors.New("stale fencing token")
}

type failOnSecondFencing struct {
	calls int
}

func (v *failOnSecondFencing) ValidateMutation(context.Context, execution.MutationOperation) error {
	v.calls++
	if v.calls >= 2 {
		return errors.New("stale fencing token")
	}
	return nil
}

type memoryCheckpointStore struct {
	mu    sync.Mutex
	items map[string]rollbackmodels.RollbackBatch
}

func newMemoryCheckpointStore() *memoryCheckpointStore {
	return &memoryCheckpointStore{items: make(map[string]rollbackmodels.RollbackBatch)}
}

func (s *memoryCheckpointStore) SaveRollbackCheckpoint(_ context.Context, batch rollbackmodels.RollbackBatch) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[batch.ID] = batch
	return nil
}

func (s *memoryCheckpointStore) LoadRollbackCheckpoint(_ context.Context, batchID string) (rollbackmodels.RollbackBatch, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.items[batchID]
	return v, ok, nil
}

type stepMutator struct {
	calls    int
	failAt   int
	executed []string
}

func (m *stepMutator) Execute(op execution.MutationOperation) (string, error) {
	m.calls++
	m.executed = append(m.executed, op.OperationID)
	if m.failAt > 0 && m.calls == m.failAt {
		return "", fmt.Errorf("forced rollback failure at call %d", m.calls)
	}
	return "ok", nil
}

func (m *stepMutator) DryRun(execution.MutationOperation) string { return "dry-run" }

func TestRollbackExecutorStaleFencingRefusesCompensationMutation(t *testing.T) {
	journal := &memoryRollbackJournal{}
	mutator := &spyRollbackMutator{}
	exec := New(
		map[string]execution.ProviderMutator{"ip_access_rules": mutator},
		journal,
		breaker.New(5, time.Minute, time.Second),
		execution.NewDriftValidator(),
		execution.NewOwnershipValidator(resources.NewRegistry()),
	)
	exec.SetFencingValidator(alwaysFailFencing{})

	err := exec.ExecuteRollback(context.Background(), rollbackmodels.RollbackBatch{
		ID: "rb-1",
		Operations: []rollbackmodels.CompensationOperation{{
			OperationID:       "op-1",
			Type:              "create",
			ResourceType:      "ip_access_rules",
			StableIdentityKey: "cf:ip_access_rules:test",
			ScopeID:           "scope-a",
			LeaseID:           "lease-old",
			FencingToken:      1,
			LeaseAction:       "rollback",
		}},
	})
	if err == nil {
		t.Fatal("expected rollback execution failure on stale fencing token")
	}
	if mutator.calls != 0 {
		t.Fatalf("mutator must not be called after stale fencing refusal, got %d", mutator.calls)
	}
	events, _ := journal.List()
	found := false
	for _, ev := range events {
		if ev.Status == "stale_fencing_token_mutation_refused" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected stale fencing audit event, got %+v", events)
	}
}

func TestRollbackExecutorPersistsAndResumesFromCheckpoint(t *testing.T) {
	journal := &memoryRollbackJournal{}
	mutator := &stepMutator{failAt: 2}
	exec := New(
		map[string]execution.ProviderMutator{"ip_access_rules": mutator},
		journal,
		breaker.New(5, time.Minute, time.Second),
		execution.NewDriftValidator(),
		execution.NewOwnershipValidator(resources.NewRegistry()),
	)
	store := newMemoryCheckpointStore()
	exec.SetCheckpointStore(store)

	batch := rollbackmodels.RollbackBatch{
		ID: "rb-resume",
		Operations: []rollbackmodels.CompensationOperation{
			{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1"},
			{OperationID: "op-2", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:2"},
			{OperationID: "op-3", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:3"},
		},
	}

	if err := exec.ExecuteRollback(context.Background(), batch); err == nil {
		t.Fatal("expected first execution to fail")
	}
	cp1, ok, err := store.LoadRollbackCheckpoint(context.Background(), batch.ID)
	if err != nil || !ok {
		t.Fatalf("expected checkpoint after failed run, err=%v ok=%v", err, ok)
	}
	if cp1.LastCompletedOpIdx != 1 {
		t.Fatalf("expected checkpoint idx=1, got %d", cp1.LastCompletedOpIdx)
	}
	if cp1.Status != rollbackmodels.StateFailed {
		t.Fatalf("expected failed checkpoint status, got %s", cp1.Status)
	}

	// Resume with a clean mutator: only remaining operations should execute.
	resumeMutator := &stepMutator{}
	exec2 := New(
		map[string]execution.ProviderMutator{"ip_access_rules": resumeMutator},
		journal,
		breaker.New(5, time.Minute, time.Second),
		execution.NewDriftValidator(),
		execution.NewOwnershipValidator(resources.NewRegistry()),
	)
	exec2.SetCheckpointStore(store)
	if err := exec2.ExecuteRollback(context.Background(), batch); err != nil {
		t.Fatalf("resume execution failed: %v", err)
	}
	if len(resumeMutator.executed) != 2 || resumeMutator.executed[0] != "op-2" || resumeMutator.executed[1] != "op-3" {
		t.Fatalf("expected resumed execution on op-2/op-3, got %+v", resumeMutator.executed)
	}
	cp2, ok, err := store.LoadRollbackCheckpoint(context.Background(), batch.ID)
	if err != nil || !ok {
		t.Fatalf("expected checkpoint after resumed run, err=%v ok=%v", err, ok)
	}
	if cp2.LastCompletedOpIdx != 3 || cp2.Status != rollbackmodels.StateCompleted {
		t.Fatalf("expected completed checkpoint idx=3, got idx=%d status=%s", cp2.LastCompletedOpIdx, cp2.Status)
	}
}

func TestRollbackExecutorShortCircuitsAlreadyCompletedCheckpoint(t *testing.T) {
	journal := &memoryRollbackJournal{}
	mutator := &stepMutator{}
	exec := New(
		map[string]execution.ProviderMutator{"ip_access_rules": mutator},
		journal,
		breaker.New(5, time.Minute, time.Second),
		execution.NewDriftValidator(),
		execution.NewOwnershipValidator(resources.NewRegistry()),
	)
	store := newMemoryCheckpointStore()
	done := rollbackmodels.RollbackBatch{
		ID:                 "rb-done",
		Status:             rollbackmodels.StateCompleted,
		LastCompletedOpIdx: 1,
		Operations: []rollbackmodels.CompensationOperation{
			{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1"},
		},
	}
	ensureRollbackPlanIdentity(&done)
	if err := store.SaveRollbackCheckpoint(context.Background(), done); err != nil {
		t.Fatalf("seed checkpoint: %v", err)
	}
	exec.SetCheckpointStore(store)

	err := exec.ExecuteRollback(context.Background(), rollbackmodels.RollbackBatch{
		ID: "rb-done",
		Operations: []rollbackmodels.CompensationOperation{
			{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1"},
		},
	})
	if err != nil {
		t.Fatalf("expected no-op on completed checkpoint, got %v", err)
	}
	if mutator.calls != 0 {
		t.Fatalf("expected no mutator call for completed checkpoint, got %d", mutator.calls)
	}
}

func TestRollbackExecutorRejectsCheckpointPlanMismatch(t *testing.T) {
	tests := []struct {
		name    string
		current rollbackmodels.RollbackBatch
		persist rollbackmodels.RollbackBatch
	}{
		{
			name: "reordered operations",
			current: rollbackmodels.RollbackBatch{
				ID: "rb-mismatch",
				Operations: []rollbackmodels.CompensationOperation{
					{OperationID: "op-2", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:2"},
					{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1"},
				},
			},
			persist: rollbackmodels.RollbackBatch{
				ID: "rb-mismatch",
				Operations: []rollbackmodels.CompensationOperation{
					{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1"},
					{OperationID: "op-2", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:2"},
				},
			},
		},
		{
			name: "changed payload",
			current: rollbackmodels.RollbackBatch{
				ID: "rb-mismatch-payload",
				Operations: []rollbackmodels.CompensationOperation{
					{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1", Payload: map[string]any{"cidr": "10.0.0.0/8"}},
				},
			},
			persist: rollbackmodels.RollbackBatch{
				ID: "rb-mismatch-payload",
				Operations: []rollbackmodels.CompensationOperation{
					{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1", Payload: map[string]any{"cidr": "192.0.2.0/24"}},
				},
			},
		},
		{
			name: "missing operation",
			current: rollbackmodels.RollbackBatch{
				ID: "rb-mismatch-missing",
				Operations: []rollbackmodels.CompensationOperation{
					{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1"},
				},
			},
			persist: rollbackmodels.RollbackBatch{
				ID: "rb-mismatch-missing",
				Operations: []rollbackmodels.CompensationOperation{
					{OperationID: "op-1", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:1"},
					{OperationID: "op-2", Type: "delete", ResourceType: "ip_access_rules", StableIdentityKey: "cf:ip_access_rules:2"},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			journal := &memoryRollbackJournal{}
			mutator := &stepMutator{}
			exec := New(
				map[string]execution.ProviderMutator{"ip_access_rules": mutator},
				journal,
				breaker.New(5, time.Minute, time.Second),
				execution.NewDriftValidator(),
				execution.NewOwnershipValidator(resources.NewRegistry()),
			)
			store := newMemoryCheckpointStore()
			ensureRollbackPlanIdentity(&tc.persist)
			if err := store.SaveRollbackCheckpoint(context.Background(), tc.persist); err != nil {
				t.Fatalf("seed checkpoint: %v", err)
			}
			exec.SetCheckpointStore(store)

			err := exec.ExecuteRollback(context.Background(), tc.current)
			if err == nil {
				t.Fatal("expected plan mismatch error")
			}
			if mutator.calls != 0 {
				t.Fatalf("expected no mutator call on plan mismatch, got %d", mutator.calls)
			}
			events, _ := journal.List()
			found := false
			for _, ev := range events {
				if ev.Status == "rollback_plan_mismatch" {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected rollback plan mismatch audit event, got %+v", events)
			}
		})
	}
}

func TestRollbackExecutorStaleFencingDuringBatchStopsRemainingOps(t *testing.T) {
	journal := &memoryRollbackJournal{}
	mutator := &stepMutator{}
	exec := New(
		map[string]execution.ProviderMutator{"ip_access_rules": mutator},
		journal,
		breaker.New(5, time.Minute, time.Second),
		execution.NewDriftValidator(),
		execution.NewOwnershipValidator(resources.NewRegistry()),
	)
	validator := &failOnSecondFencing{}
	exec.SetFencingValidator(validator)
	store := newMemoryCheckpointStore()
	exec.SetCheckpointStore(store)

	batch := rollbackmodels.RollbackBatch{
		ID: "rb-fencing-race",
		Operations: []rollbackmodels.CompensationOperation{
			{
				OperationID:       "op-1",
				Type:              "delete",
				ResourceType:      "ip_access_rules",
				StableIdentityKey: "cf:ip_access_rules:1",
				ScopeID:           "scope-a",
				LeaseID:           "lease-current",
				FencingToken:      7,
				LeaseAction:       "rollback",
			},
			{
				OperationID:       "op-2",
				Type:              "delete",
				ResourceType:      "ip_access_rules",
				StableIdentityKey: "cf:ip_access_rules:2",
				ScopeID:           "scope-a",
				LeaseID:           "lease-current",
				FencingToken:      7,
				LeaseAction:       "rollback",
			},
		},
	}

	err := exec.ExecuteRollback(context.Background(), batch)
	if err == nil {
		t.Fatal("expected stale fencing failure on second operation")
	}
	if mutator.calls != 1 {
		t.Fatalf("expected one completed mutation before stale fencing stop, got %d", mutator.calls)
	}
	cp, ok, loadErr := store.LoadRollbackCheckpoint(context.Background(), batch.ID)
	if loadErr != nil || !ok {
		t.Fatalf("expected persisted checkpoint after stale fencing stop, err=%v ok=%v", loadErr, ok)
	}
	if cp.Status != rollbackmodels.StateFailed || cp.LastCompletedOpIdx != 1 {
		t.Fatalf("expected failed checkpoint with idx=1, got status=%s idx=%d", cp.Status, cp.LastCompletedOpIdx)
	}
}
