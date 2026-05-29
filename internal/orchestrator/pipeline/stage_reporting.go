package pipeline

import (
	"context"

	"github.com/jm/security-automation-go/internal/reconciliation"
	rtmodels "github.com/jm/security-automation-go/internal/runtime/models"
	"go.opentelemetry.io/otel/trace"
)

func (o *Orchestrator) runReportingStage(ctx context.Context, tracer trace.Tracer, plan *reconciliation.Plan, snapshotID string) {
	if o.abuseClient == nil {
		return
	}
	_, abuseSpan := tracer.Start(ctx, "abuseipdb.translate")
	defer abuseSpan.End()

	reports, err := o.abuseClient.Translator.Translate(plan)
	if err != nil {
		abuseSpan.RecordError(err)
		o.bus.Emit(rtmodels.EventQuarantined, snapshotID, map[string]interface{}{
			"reason": "abuseipdb_translation_failed",
			"error":  err.Error(),
		})
		return
	}
	_ = reports
}
