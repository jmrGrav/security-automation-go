package rollback_test

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/rollback/executor"
	"github.com/jm/security-automation-go/internal/rollback/models"
	"github.com/jm/security-automation-go/internal/rollback/planner"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/snapshot"
)

type mockMutator struct {
	executed bool
}

func (m *mockMutator) Execute(op execution.MutationOperation) (string, error) {
	m.executed = true
	return "rev-123", nil
}

func (m *mockMutator) DryRun(op execution.MutationOperation) string {
	return "reversing"
}

func TestRollback_Planner_ReverseOrder(t *testing.T) {
	p := planner.New()

	forwardBatch := execution.MutationBatch{
		ID: "b1",
		Operations: []execution.MutationOperation{
			{OperationID: "o1", Type: reconciliation.OpCreate, StableIdentityKey: "k1"},
			{OperationID: "o2", Type: reconciliation.OpCreate, StableIdentityKey: "k2"},
		},
	}

	rollback, err := p.GenerateRollbackBatch(forwardBatch, "testing")
	if err != nil {
		t.Fatalf("failed to generate rollback: %v", err)
	}

	if len(rollback.Operations) != 2 {
		t.Fatalf("expected 2 operations, got %d", len(rollback.Operations))
	}

	// Verify reverse order: o2 should be first in rollback
	if rollback.Operations[0].OriginatingOpID != "o2" {
		t.Errorf("expected first rollback op to be o2, got %s", rollback.Operations[0].OriginatingOpID)
	}
	if rollback.Operations[0].Type != reconciliation.OpDelete {
		t.Errorf("expected o2 (create) to reverse to delete, got %s", rollback.Operations[0].Type)
	}
}

func TestRollback_Executor_Success(t *testing.T) {
	j := journal.NewJSONLJournal(t.TempDir() + "/audit.jsonl")
	cb := breaker.New(5, time.Minute, time.Minute)

	mut := &mockMutator{}
	mutators := map[string]execution.ProviderMutator{
		string(snapshot.ResourceIPAccessRules): mut,
	}

	reg := resources.NewRegistry()
	drift := execution.NewDriftValidator()
	owner := execution.NewOwnershipValidator(reg)

	exec := executor.New(mutators, j, cb, drift, owner)

	batch := models.RollbackBatch{
		ID: "rb1",
		Operations: []models.CompensationOperation{
			{OperationID: "c1", ResourceType: string(snapshot.ResourceIPAccessRules), StableIdentityKey: "k1", Type: reconciliation.OpDelete},
		},
	}

	err := exec.ExecuteRollback(context.Background(), batch)
	if err != nil {
		t.Fatalf("ExecuteRollback failed: %v", err)
	}

	if !mut.executed {
		t.Error("mutator was not executed for rollback")
	}
}
