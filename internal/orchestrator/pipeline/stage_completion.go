package pipeline

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/orchestrator/result"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/snapshot"
	"go.opentelemetry.io/otel/trace"
)

func (o *Orchestrator) runCompletionStage(ctx context.Context, res *result.PipelineResult, snap *snapshot.Snapshot, plan *reconciliation.Plan, span trace.Span) error {
	o.health.RecordSuccess()
	metrics.DaemonHealth.Set(1)
	res.Success = true
	res.Duration = time.Since(res.StartTime)
	o.runTelemetryStage(snap, plan, span)
	_ = o.sm.Transition(ctx, models.StatusValidating, "verifying convergence")
	_ = o.sm.Transition(ctx, models.StatusConverged, "convergence confirmed")
	_ = o.sm.Transition(ctx, models.StatusIdle, "run completed")
	return nil
}
