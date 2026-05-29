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

func TestSuppressionPersistsEvidence(t *testing.T) {
	reporter := &fakeReporter{}
	recorder := &sinks.RecorderSink{}
	evidence := &fakeEvidenceStore{}
	service := reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute)
	service.SetEvidenceStore(evidence)
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "8.8.8.8", URI: "/favicon.ico", Timestamp: time.Now().UTC(), Hits: 1, WindowSec: 300,
	})

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed {
		t.Fatalf("expected suppression, got %+v", result)
	}
	if len(evidence.evidence) != 1 || !evidence.evidence[0].Suppressed {
		t.Fatalf("expected persisted suppression evidence, got %+v", evidence.evidence)
	}
	if result.TelemetryEvent.Metadata["evidence_id"] == "" {
		t.Fatalf("expected telemetry evidence id, got %+v", result.TelemetryEvent)
	}
}
