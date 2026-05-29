package pipeline

import (
	"context"

	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/snapshot"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

func (o *Orchestrator) runTranslationStage(ctx context.Context, tracer trace.Tracer, plan *reconciliation.Plan, provenance snapshot.ProvenanceMetadata) ([]csmodels.ExecutableOperation, error) {
	_, translationSpan := tracer.Start(ctx, "crowdsec.translate")
	defer translationSpan.End()

	actions, err := o.csTranslator.Translate(plan, provenance)
	if err != nil {
		metrics.ReconciliationFailuresTotal.Inc()
		translationSpan.RecordError(err)
		return nil, err
	}
	translationSpan.SetAttributes(attribute.Int("object.count", len(actions)))
	return actions, nil
}
