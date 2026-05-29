package pipeline

import (
	"context"
	"time"

	polmodels "github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/reconciliation"
	rollbackmodels "github.com/jm/security-automation-go/internal/rollback/models"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func (o *Orchestrator) runAdmissionStage(ctx context.Context, tracer trace.Tracer, plan *reconciliation.Plan, runTraceID string) (polmodels.AdmissionDecision, error) {
	resourceIDs := make([]string, 0, len(plan.Operations))
	for _, op := range plan.Operations {
		resourceIDs = append(resourceIDs, op.TargetID)
	}

	admCtx, admSpan := tracer.Start(ctx, "policy.admission")
	defer admSpan.End()

	admDecision, err := o.admission.Authorize(admCtx, polmodels.EvaluationContext{
		Timestamp:     time.Now().UTC(),
		TargetType:    "mutation",
		MutationCount: len(plan.Operations),
		ResourceIDs:   resourceIDs,
		BreakerState:  o.breaker.GetState(),
		TraceID:       runTraceID,
		PlanID:        plan.PlanID,
	})
	if err != nil {
		admSpan.RecordError(err)
		return polmodels.AdmissionDecision{}, err
	}
	admSpan.SetAttributes(
		attribute.String("admission.decision", string(admDecision.Decision)),
		attribute.Bool("admission.allowed", admDecision.Allowed),
	)
	return admDecision, nil
}

func (o *Orchestrator) runRollbackAdmissionStage(ctx context.Context, batch rollbackmodels.RollbackBatch) (polmodels.AdmissionDecision, error) {
	resourceIDs := make([]string, 0, len(batch.Operations))
	for _, op := range batch.Operations {
		id := op.StableIdentityKey
		if id == "" {
			id = op.ProviderObjectID
		}
		if id == "" {
			id = op.OperationID
		}
		if id != "" {
			resourceIDs = append(resourceIDs, id)
		}
	}

	return o.admission.Authorize(ctx, polmodels.EvaluationContext{
		Timestamp:     time.Now().UTC(),
		TargetType:    "rollback_mutation",
		MutationCount: len(batch.Operations),
		ResourceIDs:   resourceIDs,
		BreakerState:  o.breaker.GetState(),
		TraceID:       batch.ID,
		PlanID:        batch.OriginatingBatchID,
	})
}
