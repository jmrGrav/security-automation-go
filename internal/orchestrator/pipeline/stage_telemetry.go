package pipeline

import (
	"time"

	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/snapshot"
	"go.opentelemetry.io/otel/trace"
)

func (o *Orchestrator) runTelemetryStage(snap *snapshot.Snapshot, plan *reconciliation.Plan, span trace.Span) {
	audit := models.AuditEvent{
		Timestamp: time.Now().UTC(),
		RunID:     snap.SnapshotID,
		Status:    "dry_run_completed",
		Metadata: map[string]interface{}{
			"op_count": len(plan.Operations),
			"trace_id": span.SpanContext().TraceID().String(),
			"span_id":  span.SpanContext().SpanID().String(),
		},
	}
	_ = o.journal.Append(audit)
	o.bus.Emit(models.EventRunCompleted, snap.SnapshotID, audit.Metadata)
}
