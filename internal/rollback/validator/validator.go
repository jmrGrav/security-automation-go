package validator

import (
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/rollback/models"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Validator ensures that a rollback plan is safe to execute.
type Validator struct{}

func New() *Validator {
	return &Validator{}
}

// ValidateBatch checks if the rollback batch can be safely applied.
func (v *Validator) ValidateBatch(batch models.RollbackBatch, current *snapshot.Snapshot) error {
	const op = "rollback.validator.ValidateBatch"

	if batch.Status == models.StateQuarantined {
		return apperr.New(op, "batch is quarantined")
	}

	for _, compOp := range batch.Operations {
		if err := v.ValidateOperation(compOp, current); err != nil {
			return apperr.Wrapf(op, err, "validation failed for compensation %s", compOp.OperationID)
		}
	}

	return nil
}

// ValidateOperation performs safety checks for a single compensation operation.
func (v *Validator) ValidateOperation(op models.CompensationOperation, current *snapshot.Snapshot) error {
	const fn = "rollback.validator.ValidateOperation"

	if op.StableIdentityKey == "" {
		return apperr.New(fn, "missing StableIdentityKey")
	}

	// 1. Ownership re-validation
	// TODO: Integrate resources.Registry

	// 2. Drift Re-validation
	if current != nil {
		found := false
		for _, obj := range current.Collection.Objects {
			if obj.StableIdentityKey == op.StableIdentityKey {
				found = true
				break
			}
		}

		switch op.Type {
		case reconciliation.OpDelete: // Compensation for Create
			if !found {
				// Object was already deleted? That's drift.
				return apperr.Newf(fn, "rollback target %s missing on remote", op.StableIdentityKey)
			}
		case reconciliation.OpCreate: // Compensation for Delete
			if found {
				// Object was already re-created?
				return apperr.Newf(fn, "rollback target %s unexpectedly present on remote", op.StableIdentityKey)
			}
		}
	}

	return nil
}
