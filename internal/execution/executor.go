package execution

import (
	"context"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/observability/tracing"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/models"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
	"go.opentelemetry.io/otel/trace"
)

// GovernedExecutor manages the safe execution of mutation batches.
type GovernedExecutor struct {
	mutators         map[string]ProviderMutator
	journal          journal.JournalStore
	breaker          *breaker.CircuitBreaker
	tracer           trace.Tracer
	driftVal         *DriftValidator
	ownerVal         *OwnershipValidator
	guard            SecurityGuard
	sink             sinks.Sink
	approvalEvidence ApprovalEvidenceStore
	fencing          FencingValidator
	now              func() time.Time
}

func NewGovernedExecutor(journal journal.JournalStore, cb *breaker.CircuitBreaker, reg *resources.Registry) *GovernedExecutor {
	return &GovernedExecutor{
		mutators: make(map[string]ProviderMutator),
		journal:  journal,
		breaker:  cb,
		tracer:   tracing.GetTracer(),
		driftVal: NewDriftValidator(),
		ownerVal: NewOwnershipValidator(reg),
		now:      func() time.Time { return time.Now().UTC() },
	}
}

func (e *GovernedExecutor) RegisterMutator(resourceType string, m ProviderMutator) {
	e.mutators[resourceType] = m
}

func (e *GovernedExecutor) GetMutators() map[string]ProviderMutator {
	return e.mutators
}

func (e *GovernedExecutor) SetSecurityGuard(guard SecurityGuard) {
	e.guard = guard
}

func (e *GovernedExecutor) SetTelemetrySink(sink sinks.Sink) {
	e.sink = sink
}

func (e *GovernedExecutor) SetApprovalEvidenceStore(store ApprovalEvidenceStore) {
	e.approvalEvidence = store
}

func (e *GovernedExecutor) SetFencingValidator(validator FencingValidator) {
	e.fencing = validator
}

func (e *GovernedExecutor) HasFencingValidator() bool {
	return e != nil && e.fencing != nil
}

func (e *GovernedExecutor) HasSecurityGuard() bool {
	return e != nil && e.guard != nil
}

func (e *GovernedExecutor) HasTelemetrySink() bool {
	return e != nil && e.sink != nil
}

func (e *GovernedExecutor) HasApprovalEvidenceStore() bool {
	return e != nil && e.approvalEvidence != nil
}

func (e *GovernedExecutor) SetClock(now func() time.Time) {
	if now != nil {
		e.now = now
	}
}

func (e *GovernedExecutor) ExecuteBatch(ctx context.Context, batch MutationBatch) error {
	const op = "execution.GovernedExecutor.ExecuteBatch"

	ctx, span := e.tracer.Start(ctx, "execution.batch", trace.WithAttributes(
		tracing.AttrBatchID.String(batch.ID),
		tracing.AttrPlanID.String(batch.PlanID),
	))
	defer span.End()

	// 1. Pre-execution safety checks
	if !e.breaker.Allow() {
		return apperr.New(op, "circuit breaker is open, refusing execution")
	}

	// 2. Ordered Execution (Delete -> Update -> Create)
	// We sort by type then resource graph dependencies (assumed handled by planner/orchestrator)
	now := e.nowUTC()
	if blocked, status, reason := batchApprovalBlock(batch, now); blocked {
		batch.Status = string(StateAwaitingApproval)
		parentID := e.recordApprovalEvidence(ctx, batch, nil, "approval_required", reason, "")
		e.recordApprovalEvidence(ctx, batch, nil, status, reason, parentID)
		return apperr.New(op, reason)
	}
	if batch.ApprovalRequired {
		e.recordApprovalEvidence(ctx, batch, nil, "approval_granted", "batch approval satisfied", "")
	}
	for i := range batch.Operations {
		if err := ctx.Err(); err != nil {
			e.breaker.RecordFailure()
			batch.Status = "failed"
			e.recordLostLeaseAbort(ctx, batch.ID, "", err)
			return apperr.Wrap(op, err)
		}
		operation := &batch.Operations[i]

		if err := e.executeSingle(ctx, operation, batch.ID); err != nil {
			e.breaker.RecordFailure()
			batch.Status = "failed"
			return apperr.Wrapf(op, err, "batch failed at operation %s", operation.OperationID)
		}
	}

	e.breaker.RecordSuccess()
	batch.Status = "completed"
	return nil
}

func (e *GovernedExecutor) executeSingle(ctx context.Context, op *MutationOperation, batchID string) error {
	const fn = "execution.GovernedExecutor.executeSingle"

	_, span := e.tracer.Start(ctx, "execution.operation", trace.WithAttributes(
		tracing.AttrOpID.String(op.OperationID),
		tracing.AttrOperationType.String(string(op.Type)),
		tracing.AttrResourceKind.String(op.ResourceType),
		tracing.AttrResourceSIK.String(op.StableIdentityKey),
	))
	defer span.End()

	mutator, ok := e.mutators[op.ResourceType]
	if !ok {
		return apperr.Newf(fn, "no mutator registered for resource type: %s", op.ResourceType)
	}

	now := e.nowUTC()
	if blocked, status, reason := operationApprovalBlock(*op, now); blocked {
		op.State = StateAwaitingApproval
		op.Error = reason
		approvalBatch := MutationBatch{
			ID:                batchID,
			ScopeID:           op.ScopeID,
			ApprovalID:        op.ApprovalID,
			ApprovalRequired:  op.ApprovalRequired,
			ApprovalStatus:    op.ApprovalStatus,
			ApprovalExpiresAt: op.ApprovalExpiresAt,
			ApprovedBy:        op.ApprovedBy,
			ApprovalReason:    op.ApprovalReason,
		}
		parentID := e.recordApprovalEvidence(ctx, approvalBatch, op, "approval_required", reason, "")
		e.recordApprovalEvidence(ctx, approvalBatch, op, status, reason, parentID)
		now := e.nowUTC()
		_ = e.journal.Append(models.AuditEvent{
			Timestamp: now,
			BatchID:   batchID,
			OpID:      op.OperationID,
			Status:    string(StateAwaitingApproval),
			Error:     op.Error,
			Metadata: map[string]interface{}{
				"approval_required": true,
				"approval_id":       op.ApprovalID,
				"approval_status":   op.ApprovalStatus,
				"approval_expires":  op.ApprovalExpiresAt,
				"approved_by":       op.ApprovedBy,
				"approval_reason":   op.ApprovalReason,
			},
		})
		return apperr.New(fn, reason)
	}
	if op.ApprovalRequired {
		e.recordApprovalEvidence(ctx, MutationBatch{
			ID:                batchID,
			ScopeID:           op.ScopeID,
			ApprovalID:        op.ApprovalID,
			ApprovalRequired:  op.ApprovalRequired,
			ApprovalStatus:    op.ApprovalStatus,
			ApprovalExpiresAt: op.ApprovalExpiresAt,
			ApprovedBy:        op.ApprovedBy,
			ApprovalReason:    op.ApprovalReason,
		}, op, "approval_granted", "operation approval satisfied", "")
	}

	op.State = StateValidating

	if e.guard != nil {
		decision, err := e.guard.EvaluateMutation(ctx, *op)
		if err != nil {
			return apperr.Wrap(fn, err)
		}
		if !decision.Allowed {
			op.State = StateQuarantined
			op.Error = decision.Reason
			now := time.Now().UTC()
			audit := models.AuditEvent{
				Timestamp: now,
				BatchID:   batchID,
				OpID:      op.OperationID,
				Status:    "quarantined",
				Error:     decision.Reason,
				Metadata: map[string]interface{}{
					"suppression_reason": decision.Reason,
					"target_ip":          decision.TargetIP,
					"source":             decision.Source,
					"rule_id":            decision.RuleID,
					"enforcement_stage":  decision.EnforcementStage,
					"risk_score":         decision.RiskScore,
					"confidence":         decision.Confidence,
				},
			}
			if decision.Reputation != nil {
				audit.Metadata["reputation_provider"] = decision.Reputation.Provider
				audit.Metadata["reputation_score"] = decision.Reputation.Score
				audit.Metadata["cache_hit"] = decision.Reputation.CacheHit
			}
			_ = e.journal.Append(audit)
			if e.sink != nil {
				_ = e.sink.Publish(ctx, tmevents.SecurityEvent{
					Timestamp:         now,
					Source:            decision.Source,
					IP:                decision.TargetIP,
					RuleID:            decision.RuleID,
					AbuseType:         "suppressed_propagation",
					RiskScore:         decision.RiskScore,
					Confidence:        decision.Confidence,
					EnforcementStage:  decision.EnforcementStage,
					Propagated:        false,
					AbuseIPDBReported: false,
					CloudflareBanned:  false,
					SuppressionReason: decision.Reason,
					Severity:          "warning",
					Metadata:          decision.Metadata,
				})
			}
			return apperr.Newf(fn, "guard suppressed mutation: %s", decision.Reason)
		}
	}

	// 1. Ownership Validation
	if err := e.ownerVal.Validate(*op); err != nil {
		op.State = StateQuarantined
		return apperr.Wrap(fn, err)
	}

	if e.fencing != nil {
		if err := e.fencing.ValidateMutation(ctx, *op); err != nil {
			op.State = StateQuarantined
			op.Error = err.Error()
			e.recordFencingRefusal(ctx, batchID, op, err)
			return apperr.Wrap(fn, err)
		}
	}

	// 2. Drift Validation (Simplified for phase 1)
	// if err := e.driftVal.Validate(*op, currentSnapshot); err != nil { ... }

	op.State = StateExecuting
	op.StartedAt = e.nowUTC()

	_ = e.journal.Append(models.AuditEvent{
		Timestamp: op.StartedAt,
		BatchID:   batchID,
		OpID:      op.OperationID,
		Status:    "executing",
		Action:    "mutation", // Map to models.ActionType if needed
		Target:    op.StableIdentityKey,
	})

	if err := ctx.Err(); err != nil {
		op.State = StateFailed
		op.Error = err.Error()
		e.recordLostLeaseAbort(ctx, batchID, op.OperationID, err)
		return apperr.Wrap(fn, err)
	}
	var resultID string
	var err error
	if contextMutator, ok := mutator.(ContextProviderMutator); ok {
		resultID, err = contextMutator.ExecuteContext(ctx, *op)
	} else {
		resultID, err = mutator.Execute(*op)
	}
	op.FinishedAt = e.nowUTC()
	duration := op.FinishedAt.Sub(op.StartedAt)

	if err != nil {
		op.State = StateFailed
		op.Error = err.Error()
		if ctx.Err() != nil || isLostLeaseCause(ctx) {
			e.recordLostLeaseAbort(ctx, batchID, op.OperationID, err)
		}
		metrics.MutationFailuresTotal.WithLabelValues(string(op.Type)).Inc()

		_ = e.journal.Append(models.AuditEvent{
			Timestamp: op.FinishedAt,
			BatchID:   batchID,
			OpID:      op.OperationID,
			Status:    "failed",
			Error:     err.Error(),
			Duration:  duration.Milliseconds(),
		})
		return err
	}

	op.State = StateCompleted
	op.ResultID = resultID
	metrics.MutationOperationsTotal.WithLabelValues(string(op.Type)).Inc()

	_ = e.journal.Append(models.AuditEvent{
		Timestamp: op.FinishedAt,
		BatchID:   batchID,
		OpID:      op.OperationID,
		Status:    "completed",
		Duration:  duration.Milliseconds(),
		Metadata:  map[string]interface{}{"result_id": resultID},
	})

	return nil
}

func (e *GovernedExecutor) recordFencingRefusal(ctx context.Context, batchID string, op *MutationOperation, err error) {
	if e == nil || op == nil {
		return
	}
	now := e.nowUTC()
	if e.journal != nil {
		_ = e.journal.Append(models.AuditEvent{
			Timestamp: now,
			BatchID:   batchID,
			OpID:      op.OperationID,
			Status:    "stale_fencing_token_mutation_refused",
			Error:     errString(err),
			Metadata: map[string]interface{}{
				"scope_id":        op.ScopeID,
				"lease_id":        op.LeaseID,
				"fencing_token":   op.FencingToken,
				"lease_action":    op.LeaseAction,
				"resource_type":   op.ResourceType,
				"recovery_needed": false,
			},
		})
	}
	if e.sink != nil {
		_ = e.sink.Publish(ctx, tmevents.SecurityEvent{
			Timestamp:         now,
			Source:            "execution",
			AbuseType:         "stale_fencing_token_mutation_refused",
			EnforcementStage:  "refused",
			Propagated:        false,
			CloudflareBanned:  false,
			SuppressionReason: "stale_fencing_token",
			Severity:          "critical",
			Metadata: map[string]any{
				"batch_id":      batchID,
				"operation_id":  op.OperationID,
				"scope_id":      op.ScopeID,
				"lease_id":      op.LeaseID,
				"fencing_token": op.FencingToken,
				"lease_action":  op.LeaseAction,
				"resource_type": op.ResourceType,
			},
		})
	}
}

func (e *GovernedExecutor) recordLostLeaseAbort(ctx context.Context, batchID string, operationID string, err error) {
	if e == nil || e.journal == nil {
		return
	}
	reason := "context_cancelled"
	if isLostLeaseCause(ctx) {
		reason = "lost_lease"
	}
	now := e.nowUTC()
	_ = e.journal.Append(models.AuditEvent{
		Timestamp: now,
		BatchID:   batchID,
		OpID:      operationID,
		Status:    "lost_lease_mutation_aborted",
		Error:     errString(err),
		Metadata: map[string]interface{}{
			"reason":          reason,
			"recovery_needed": true,
		},
	})
	if e.sink != nil {
		_ = e.sink.Publish(context.Background(), tmevents.SecurityEvent{
			Timestamp:         now,
			Source:            "execution",
			AbuseType:         "lost_lease_mutation_aborted",
			EnforcementStage:  "aborted",
			Propagated:        false,
			CloudflareBanned:  false,
			SuppressionReason: reason,
			Severity:          "critical",
			Metadata: map[string]any{
				"batch_id":        batchID,
				"operation_id":    operationID,
				"recovery_needed": true,
			},
		})
	}
}

func isLostLeaseCause(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	cause := context.Cause(ctx)
	return cause != nil && strings.Contains(strings.ToLower(cause.Error()), "lost lease")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func (e *GovernedExecutor) recordApprovalEvidence(ctx context.Context, batch MutationBatch, op *MutationOperation, event string, reason string, parentEvidenceID string) string {
	if e == nil || e.approvalEvidence == nil {
		return ""
	}
	now := e.nowUTC()
	ev := ApprovalEvidence{
		EvidenceID:       approvalEvidenceID(batch, op, now),
		Timestamp:        now,
		Event:            event,
		ScopeID:          approvalScope(batch, op),
		BatchID:          batch.ID,
		PlanID:           batch.PlanID,
		OperationID:      decisionTargetID(op),
		ApprovalID:       approvalID(batch, op),
		Status:           approvalStatus(batch, op),
		Reason:           reason,
		ApprovedBy:       approvedBy(batch, op),
		RequestedAt:      now,
		DecidedAt:        now,
		ExpiresAt:        approvalExpiresAt(batch, op),
		ApprovalReason:   approvalReason(batch, op),
		MutationType:     mutationType(op),
		RiskLevel:        riskLevel(batch, op),
		ParentEvidenceID: parentEvidenceID,
		LineageID:        approvalLineageID(batch, op),
		DecisionHash:     approvalDecisionHash(batch, op, event, reason),
		Metadata: map[string]any{
			"approval_required": approvalRequired(batch, op),
			"operation_state":   operationState(op),
		},
	}
	_ = e.approvalEvidence.Append(ctx, ev)
	return ev.EvidenceID
}

func operationState(op *MutationOperation) string {
	if op == nil {
		return ""
	}
	return string(op.State)
}

func (e *GovernedExecutor) nowUTC() time.Time {
	if e == nil || e.now == nil {
		return time.Now().UTC()
	}
	return e.now().UTC()
}

func batchApprovalBlock(batch MutationBatch, now time.Time) (bool, string, string) {
	if !batch.ApprovalRequired {
		return false, "", ""
	}
	switch batch.ApprovalStatus {
	case ApprovalRejected:
		return true, "approval_denied", "batch approval denied before execution"
	case ApprovalApproved:
		if !batch.ApprovalExpiresAt.IsZero() && now.After(batch.ApprovalExpiresAt.UTC()) {
			return true, "approval_expired", "batch approval expired before execution"
		}
		return false, "", ""
	default:
		return true, "awaiting_approval", "batch requires approval before execution"
	}
}

func operationApprovalBlock(op MutationOperation, now time.Time) (bool, string, string) {
	if !op.ApprovalRequired {
		return false, "", ""
	}
	switch op.ApprovalStatus {
	case ApprovalRejected:
		return true, "approval_denied", "operation approval denied before execution"
	case ApprovalApproved:
		if !op.ApprovalExpiresAt.IsZero() && now.After(op.ApprovalExpiresAt.UTC()) {
			return true, "approval_expired", "operation approval expired before execution"
		}
		return false, "", ""
	default:
		return true, "awaiting_approval", "approval required before execution"
	}
}
