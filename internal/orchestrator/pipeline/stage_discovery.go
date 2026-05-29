package pipeline

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/observability/tracing"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/snapshot"
	"go.opentelemetry.io/otel/trace"
)

func (o *Orchestrator) runDiscoveryStage(ctx context.Context, tracer trace.Tracer, zoneID string, rt snapshot.ResourceType) ([]cfmodels.IPAccessRule, error) {
	if !o.gov.Allow(o.deriveScope(zoneID), "cloudflare", governor.ResourceRequest, 1) {
		return nil, apperr.New("orchestrator.pipeline.runDiscoveryStage", "global resource budget exceeded")
	}
	if err := o.sm.Transition(ctx, models.StatusDiscovering, "starting dry-run"); err != nil {
		return nil, err
	}
	if !o.breaker.Allow() {
		metrics.BreakerState.Set(1)
		o.bus.Emit(models.EventBreakerState, "", map[string]interface{}{"state": "open"})
		_ = o.sm.Transition(ctx, models.StatusFailed, "breaker open")
		return nil, apperr.New("orchestrator.pipeline.runDiscoveryStage", "circuit breaker is open")
	}
	metrics.BreakerState.Set(0)

	discoveryCtx, discoverySpan := tracer.Start(ctx, "discovery.cloudflare", trace.WithAttributes(
		tracing.AttrCFEndpoint.String(string(rt)),
	))
	defer discoverySpan.End()

	start := time.Now()
	rules, err := o.cfClient.Discovery.ListIPAccessRules(discoveryCtx, zoneID)
	metrics.DiscoveryDurationSeconds.Observe(time.Since(start).Seconds())
	discoverySpan.SetAttributes(tracing.AttrObjectCount.Int(len(rules)))
	if err != nil {
		metrics.ReconciliationFailuresTotal.Inc()
		o.health.RecordFailure()
		discoverySpan.RecordError(err)
		_ = o.sm.Transition(ctx, models.StatusFailed, "discovery failed")
		return nil, err
	}
	return rules, nil
}
