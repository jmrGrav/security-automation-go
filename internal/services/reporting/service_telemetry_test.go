package reporting_test

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	tmevents "github.com/jm/security-automation-go/internal/telemetry/events"
)

type failingSink struct{}

func (failingSink) Publish(context.Context, tmevents.SecurityEvent) error {
	return context.DeadlineExceeded
}

func TestTelemetrySinkFailureDoesNotFailDecisionPath(t *testing.T) {
	reporter := &fakeReporter{}
	service := reporting.New(reporter, failingSink{}, trust.DefaultRegistry(), time.Minute)
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "8.8.8.8", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: time.Now().UTC(), Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process should stay fail-open on telemetry error: %v", err)
	}
	if !result.Reported || len(reporter.reports) != 1 {
		t.Fatalf("expected report despite telemetry failure, got %+v reports=%d", result, len(reporter.reports))
	}
}
