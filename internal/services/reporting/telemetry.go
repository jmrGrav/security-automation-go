package reporting

import (
	"context"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

func (s *Service) publish(ctx context.Context, event tmevents.SecurityEvent) error {
	if s == nil || s.sink == nil {
		return nil
	}
	if err := s.sink.Publish(ctx, event); err != nil {
		metrics.TelemetryPublishFailuresTotal.Inc()
		return err
	}
	return nil
}

func (s *Service) Observe(ctx context.Context, event tmevents.SecurityEvent) {
	if s != nil {
		s.recordObservedEvidence(ctx, event)
	}
	_ = s.publish(ctx, event)
}
