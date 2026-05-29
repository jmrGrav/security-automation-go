package pipeline

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/policy/admission"
	polengine "github.com/jm/security-automation-go/internal/policy/engine"
	rollbackmodels "github.com/jm/security-automation-go/internal/rollback/models"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
)

func TestRunRollbackAdmissionStage_AllowsWithOwnedUpdateCapability(t *testing.T) {
	t.Parallel()

	ownerRes := ownership.NewResolver()
	ownerRes.RegisterDomain(ownership.OwnershipDomain{
		ID:           "cf-sync",
		Priority:     100,
		Capabilities: []ownership.Right{ownership.RightUpdate},
	})
	ctrl := admission.New(polengine.New(nil), nil, ownerRes, nil, nil, slog.Default())
	orch := &Orchestrator{
		admission: ctrl,
		breaker:   breaker.New(5, time.Minute, time.Minute),
	}

	decision, err := orch.runRollbackAdmissionStage(context.Background(), rollbackmodels.RollbackBatch{
		ID: "rb-1",
		Operations: []rollbackmodels.CompensationOperation{
			{OperationID: "op-1", StableIdentityKey: "resource-1"},
		},
	})
	if err != nil {
		t.Fatalf("run rollback admission: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected rollback admission allowed, got denied: %s", decision.Reason)
	}
}

func TestRunRollbackAdmissionStage_DeniesWithoutUpdateCapability(t *testing.T) {
	t.Parallel()

	ownerRes := ownership.NewResolver()
	ownerRes.RegisterDomain(ownership.OwnershipDomain{
		ID:           "cf-sync",
		Priority:     100,
		Capabilities: []ownership.Right{ownership.RightCreate},
	})
	ctrl := admission.New(polengine.New(nil), nil, ownerRes, nil, nil, slog.Default())
	orch := &Orchestrator{
		admission: ctrl,
		breaker:   breaker.New(5, time.Minute, time.Minute),
	}

	decision, err := orch.runRollbackAdmissionStage(context.Background(), rollbackmodels.RollbackBatch{
		ID: "rb-2",
		Operations: []rollbackmodels.CompensationOperation{
			{OperationID: "op-1", StableIdentityKey: "resource-1"},
		},
	})
	if err != nil {
		t.Fatalf("run rollback admission: %v", err)
	}
	if decision.Allowed {
		t.Fatalf("expected rollback admission denied")
	}
}
