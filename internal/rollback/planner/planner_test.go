package planner_test

import (
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/rollback/planner"
)

func TestGenerateRollbackBatch_OpUpdateReturnsError(t *testing.T) {
	p := planner.New()
	batch := execution.MutationBatch{
		ID: "batch-1",
		Operations: []execution.MutationOperation{
			{
				OperationID:       "op-1",
				Type:              reconciliation.OpUpdate,
				ResourceType:      "cf:rule",
				StableIdentityKey: "cf:rule:abc",
				Payload:           map[string]string{"expression": "new-expr"},
			},
		},
	}
	_, err := p.GenerateRollbackBatch(batch, "test rollback")
	if err == nil {
		t.Error("expected error for OpUpdate rollback (PreviousPayload not available)")
	}
	if err != nil && !strings.Contains(err.Error(), "PreviousPayload") && !strings.Contains(err.Error(), "not yet supported") {
		t.Errorf("error message should mention the reason, got: %v", err)
	}
}

func TestGenerateRollbackBatch_OpDeleteGeneratesCreate(t *testing.T) {
	p := planner.New()
	batch := execution.MutationBatch{
		ID: "batch-1",
		Operations: []execution.MutationOperation{
			{
				OperationID:       "op-1",
				Type:              reconciliation.OpDelete,
				ResourceType:      "cf:rule",
				StableIdentityKey: "cf:rule:abc",
				Payload:           map[string]string{"expression": "original"},
			},
		},
	}
	rb, err := p.GenerateRollbackBatch(batch, "test rollback")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rb.Operations) != 1 {
		t.Fatalf("expected 1 compensation op, got %d", len(rb.Operations))
	}
	if rb.Operations[0].Type != reconciliation.OpCreate {
		t.Errorf("OpDelete compensation should be OpCreate, got %v", rb.Operations[0].Type)
	}
}
