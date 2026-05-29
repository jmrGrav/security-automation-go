package reporting

import (
	"context"

	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

func (s *Service) publish(ctx context.Context, event tmevents.SecurityEvent) error {
	if s == nil || s.sink == nil {
		return nil
	}
	return s.sink.Publish(ctx, event)
}

func (s *Service) Observe(ctx context.Context, event tmevents.SecurityEvent) {
	if s != nil {
		s.recordObservedEvidence(ctx, event)
	}
	_ = s.publish(ctx, event)
}
