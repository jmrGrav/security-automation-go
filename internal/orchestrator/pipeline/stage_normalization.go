package pipeline

import (
	"context"

	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/observability/tracing"
	"github.com/jm/security-automation-go/internal/orchestrator/result"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/snapshot"
	"go.opentelemetry.io/otel/trace"
)

func (o *Orchestrator) runNormalizationStage(ctx context.Context, tracer trace.Tracer, rt snapshot.ResourceType, rules []cfmodels.IPAccessRule, provenance snapshot.ProvenanceMetadata, res *result.PipelineResult) (*snapshot.Snapshot, error) {
	_, assemblySpan := tracer.Start(ctx, "snapshot.assemble")
	defer assemblySpan.End()

	snap, err := o.runSnapshotStage(rt, rules, provenance)
	if err != nil {
		metrics.ReconciliationFailuresTotal.Inc()
		assemblySpan.RecordError(err)
		_ = o.sm.Transition(ctx, models.StatusFailed, "assembly failed")
		return nil, err
	}
	assemblySpan.SetAttributes(
		tracing.AttrObjectCount.Int(snap.Collection.ObjectCount),
		tracing.AttrSnapshotChecksum.String(snap.Integrity.SnapshotChecksum),
	)

	if res != nil {
		res.Snapshot.ObjectCount = snap.Collection.ObjectCount
		res.Snapshot.Checksum = snap.Integrity.SnapshotChecksum
	}
	return snap, nil
}
