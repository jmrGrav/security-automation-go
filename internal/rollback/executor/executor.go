package executor

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/observability/tracing"
	"github.com/jm/security-automation-go/internal/rollback/models"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	runmodels "github.com/jm/security-automation-go/internal/runtime/models"
	"go.opentelemetry.io/otel/trace"
)

// Executor manages the safe application of compensation operations.
type Executor struct {
	mutators    map[string]execution.ProviderMutator
	journal     journal.JournalStore
	breaker     *breaker.CircuitBreaker
	tracer      trace.Tracer
	driftVal    *execution.DriftValidator
	ownerVal    *execution.OwnershipValidator
	fencingVal  execution.FencingValidator
	checkpoints RollbackCheckpointStore
}

type RollbackCheckpointStore interface {
	SaveRollbackCheckpoint(ctx context.Context, batch models.RollbackBatch) error
	LoadRollbackCheckpoint(ctx context.Context, batchID string) (models.RollbackBatch, bool, error)
}

func New(mutators map[string]execution.ProviderMutator, journal journal.JournalStore, cb *breaker.CircuitBreaker, drift *execution.DriftValidator, owner *execution.OwnershipValidator) *Executor {
	return &Executor{
		mutators: mutators,
		journal:  journal,
		breaker:  cb,
		tracer:   tracing.GetTracer(),
		driftVal: drift,
		ownerVal: owner,
	}
}

func (e *Executor) SetFencingValidator(validator execution.FencingValidator) {
	e.fencingVal = validator
}

func (e *Executor) HasFencingValidator() bool {
	return e != nil && e.fencingVal != nil
}

func (e *Executor) SetCheckpointStore(store RollbackCheckpointStore) {
	e.checkpoints = store
}

func (e *Executor) HasCheckpointStore() bool {
	return e != nil && e.checkpoints != nil
}

func (e *Executor) ExecuteRollback(ctx context.Context, batch models.RollbackBatch) error {
	const op = "rollback.executor.ExecuteRollback"

	ctx, span := e.tracer.Start(ctx, "rollback.batch", trace.WithAttributes(
		tracing.AttrBatchID.String(batch.ID),
	))
	defer span.End()

	if !e.breaker.Allow() {
		return apperr.New(op, "circuit breaker is open, refusing rollback")
	}

	if e.checkpoints != nil {
		persisted, ok, err := e.checkpoints.LoadRollbackCheckpoint(ctx, batch.ID)
		if err != nil {
			return apperr.Wrap(op, err)
		}
		if ok {
			if persisted.LastCompletedOpIdx > batch.LastCompletedOpIdx {
				batch.LastCompletedOpIdx = persisted.LastCompletedOpIdx
			}
			if persisted.Status == models.StateCompleted && persisted.LastCompletedOpIdx >= len(batch.Operations) {
				return nil
			}
			if !persisted.StartedAt.IsZero() {
				batch.StartedAt = persisted.StartedAt
			}
		}
	}

	batch.Status = models.StateExecuting
	if batch.StartedAt.IsZero() {
		batch.StartedAt = time.Now().UTC()
	}
	if e.checkpoints != nil {
		if err := e.checkpoints.SaveRollbackCheckpoint(ctx, batch); err != nil {
			return apperr.Wrap(op, err)
		}
	}

	_ = e.journal.Append(runmodels.AuditEvent{
		Timestamp: batch.StartedAt,
		RunID:     batch.ID,
		Status:    "rollback_started",
		Metadata:  map[string]interface{}{"originating_batch": batch.OriginatingBatchID},
	})

	for i := batch.LastCompletedOpIdx; i < len(batch.Operations); i++ {
		compOp := &batch.Operations[i]

		if err := e.executeSingle(ctx, compOp, batch.ID); err != nil {
			e.breaker.RecordFailure()
			batch.Status = models.StateFailed
			batch.FinishedAt = time.Now().UTC()
			if e.checkpoints != nil {
				_ = e.checkpoints.SaveRollbackCheckpoint(ctx, batch)
			}

			_ = e.journal.Append(runmodels.AuditEvent{
				Timestamp: batch.FinishedAt,
				RunID:     batch.ID,
				Status:    "rollback_failed",
				Error:     err.Error(),
			})
			return apperr.Wrapf(op, err, "rollback batch failed at operation %s", compOp.OperationID)
		}

		batch.LastCompletedOpIdx = i + 1
		if e.checkpoints != nil {
			if err := e.checkpoints.SaveRollbackCheckpoint(ctx, batch); err != nil {
				return apperr.Wrap(op, err)
			}
		}
	}

	e.breaker.RecordSuccess()
	batch.Status = models.StateCompleted
	batch.FinishedAt = time.Now().UTC()
	if e.checkpoints != nil {
		if err := e.checkpoints.SaveRollbackCheckpoint(ctx, batch); err != nil {
			return apperr.Wrap(op, err)
		}
	}

	_ = e.journal.Append(runmodels.AuditEvent{
		Timestamp: batch.FinishedAt,
		RunID:     batch.ID,
		Status:    "rollback_completed",
	})

	return nil
}

func (e *Executor) executeSingle(ctx context.Context, op *models.CompensationOperation, batchID string) error {
	const fn = "rollback.executor.executeSingle"

	_, span := e.tracer.Start(ctx, "rollback.operation", trace.WithAttributes(
		tracing.AttrOpID.String(op.OperationID),
		tracing.AttrResourceKind.String(op.ResourceType),
		tracing.AttrResourceSIK.String(op.StableIdentityKey),
	))
	defer span.End()

	mutator, ok := e.mutators[op.ResourceType]
	if !ok {
		return apperr.Newf(fn, "no mutator registered for resource type: %s", op.ResourceType)
	}

	op.State = models.StateValidating

	// 1. Validation (Drift/Ownership)
	execOp := execution.MutationOperation{
		OperationID:       op.OperationID,
		ScopeID:           op.ScopeID,
		Type:              op.Type,
		ResourceType:      op.ResourceType,
		StableIdentityKey: op.StableIdentityKey,
		Payload:           op.Payload,
		ProviderObjectID:  op.ProviderObjectID,
		ExpectedETag:      op.ExpectedETag,
		LeaseID:           op.LeaseID,
		FencingToken:      op.FencingToken,
		LeaseAction:       op.LeaseAction,
	}

	if err := e.ownerVal.Validate(execOp); err != nil {
		op.State = models.StateQuarantined
		return apperr.Wrap(fn, err)
	}
	if e.fencingVal != nil {
		if err := e.fencingVal.ValidateMutation(ctx, execOp); err != nil {
			op.State = models.StateQuarantined
			op.Error = err.Error()
			_ = e.journal.Append(runmodels.AuditEvent{
				Timestamp: time.Now().UTC(),
				BatchID:   batchID,
				OpID:      op.OperationID,
				Status:    "stale_fencing_token_mutation_refused",
				Error:     err.Error(),
				Metadata: map[string]interface{}{
					"scope_id":        op.ScopeID,
					"lease_id":        op.LeaseID,
					"fencing_token":   op.FencingToken,
					"lease_action":    op.LeaseAction,
					"resource_type":   op.ResourceType,
					"recovery_needed": false,
				},
			})
			return apperr.Wrap(fn, err)
		}
	}

	op.State = models.StateExecuting
	op.StartedAt = time.Now().UTC()

	_ = e.journal.Append(runmodels.AuditEvent{
		Timestamp: op.StartedAt,
		BatchID:   batchID,
		OpID:      op.OperationID,
		Status:    "executing_compensation",
		Action:    "rollback",
		Target:    op.StableIdentityKey,
	})

	var resultID string
	var err error
	if contextMutator, ok := mutator.(execution.ContextProviderMutator); ok {
		resultID, err = contextMutator.ExecuteContext(ctx, execOp)
	} else {
		resultID, err = mutator.Execute(execOp)
	}
	op.FinishedAt = time.Now().UTC()
	duration := op.FinishedAt.Sub(op.StartedAt)

	if err != nil {
		op.State = models.StateFailed
		op.Error = err.Error()
		span.RecordError(err)

		_ = e.journal.Append(runmodels.AuditEvent{
			Timestamp: op.FinishedAt,
			BatchID:   batchID,
			OpID:      op.OperationID,
			Status:    "compensation_failed",
			Error:     err.Error(),
			Duration:  duration.Milliseconds(),
		})
		return err
	}

	op.State = models.StateCompleted
	op.ResultID = resultID

	_ = e.journal.Append(runmodels.AuditEvent{
		Timestamp: op.FinishedAt,
		BatchID:   batchID,
		OpID:      op.OperationID,
		Status:    "compensation_completed",
		Duration:  duration.Milliseconds(),
		Metadata:  map[string]interface{}{"result_id": resultID},
	})

	return nil
}
