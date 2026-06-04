package planner

import (
	"fmt"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/rollback/models"
)

// Planner generates compensation operations for forward mutations.
type Planner struct{}

func New() *Planner {
	return &Planner{}
}

// GenerateRollbackBatch creates a rollback batch for a given mutation batch.
func (p *Planner) GenerateRollbackBatch(forward execution.MutationBatch, reason string) (models.RollbackBatch, error) {
	const op = "rollback.planner.GenerateRollbackBatch"

	rollback := models.RollbackBatch{
		ID:                 fmt.Sprintf("rb-%s-%d", forward.ID, time.Now().Unix()),
		OriginatingBatchID: forward.ID,
		CreatedAt:          time.Now().UTC(),
		Status:             models.StatePlanned,
		Reason:             reason,
	}

	// We must reverse the execution order to respect graph dependencies
	// (Create child -> Create parent reverses to Delete parent -> Delete child)
	// Actually, forward is Delete -> Update -> Create.
	// Rollback should be Create -> Update -> Delete in reverse index order.
	for i := len(forward.Operations) - 1; i >= 0; i-- {
		forwardOp := forward.Operations[i]

		compOp, err := p.generateCompensation(forwardOp)
		if err != nil {
			return rollback, apperr.Wrapf(op, err, "failed to generate compensation for %s", forwardOp.OperationID)
		}

		rollback.Operations = append(rollback.Operations, compOp)
	}

	return rollback, nil
}

func (p *Planner) generateCompensation(forward execution.MutationOperation) (models.CompensationOperation, error) {
	const op = "rollback.planner.generateCompensation"

	comp := models.CompensationOperation{
		OperationID:       fmt.Sprintf("comp-%s", forward.OperationID),
		OriginatingOpID:   forward.OperationID,
		ScopeID:           forward.ScopeID,
		ResourceType:      forward.ResourceType,
		StableIdentityKey: forward.StableIdentityKey,
		State:             models.StatePlanned,
		ProviderObjectID:  forward.ProviderObjectID,
		LeaseID:           forward.LeaseID,
		FencingToken:      forward.FencingToken,
		LeaseAction:       forward.LeaseAction,
	}

	if comp.ProviderObjectID == "" {
		comp.ProviderObjectID = forward.ResultID
	}

	switch forward.Type {
	case reconciliation.OpCreate:
		// Undo creation by deleting the resource
		comp.Type = reconciliation.OpDelete
		comp.ExpectedPrecondition = forward.Payload // We expect the created state
	case reconciliation.OpDelete:
		// Undo deletion by restoring the original state
		comp.Type = reconciliation.OpCreate
		comp.Payload = forward.Payload // Re-create with original attributes
	case reconciliation.OpUpdate:
		// Cannot generate correct compensation: MutationOperation only carries the
		// forward payload, not the previous state. Return an error until PreviousPayload
		// is added to MutationOperation.
		return comp, apperr.New(op, "rollback for OpUpdate requires PreviousPayload which is not yet supported")
	default:
		return comp, apperr.Newf(op, "unsupported forward operation type for rollback: %s", forward.Type)
	}

	return comp, nil
}
