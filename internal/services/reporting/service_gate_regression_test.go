package reporting_test

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

func TestDecisionGateExtractionPreservesDuplicateSuppression(t *testing.T) {
	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Hour)
	service.SetClock(func() time.Time { return base })

	event, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP:        "8.8.8.8",
		URI:       "/search?q=union+select+1",
		UserAgent: "sqlmap",
		Timestamp: base,
		Hits:      10,
		WindowSec: 300,
		RuleID:    "r1",
		Action:    "block",
		Source:    "cloudflare",
		Hostname:  "arleo.eu",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	first, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("first process: %v", err)
	}
	second, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("second process: %v", err)
	}
	if !first.Reported {
		t.Fatalf("first decision must still report, got %+v", first)
	}
	if !second.Suppressed || second.SuppressionReason != "duplicate_report" {
		t.Fatalf("duplicate suppression changed after gate extraction: first=%+v second=%+v", first, second)
	}
	if len(reporter.Reports()) != 1 {
		t.Fatalf("expected exactly one upstream report, got %d", len(reporter.Reports()))
	}
}
