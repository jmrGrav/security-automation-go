package reporting_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

func TestEvidenceStoreFailureDoesNotPanicOrBlockSuppression(t *testing.T) {
	reporter := &fakeReporter{}
	recorder := &sinks.RecorderSink{}
	evidence := &fakeEvidenceStore{err: errors.New("sqlite write failed")}
	service := reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute)
	service.SetEvidenceStore(evidence)

	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "8.8.8.8", URI: "/favicon.ico", Timestamp: time.Now().UTC(), Hits: 1, WindowSec: 60,
	})
	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed || result.SuppressionReason == "" {
		t.Fatalf("expected suppressed result, got %+v", result)
	}
	if len(recorder.Events) != 1 {
		t.Fatalf("expected telemetry despite evidence store failure, got %d", len(recorder.Events))
	}
}

func TestDuplicateSameIPAcrossSourcesWithin24hOnlyOneReportSent(t *testing.T) {
	base := time.Date(2026, 5, 27, 16, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	store := newFakeDedupStore()
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportDedupStore(store)
	service.SetClock(func() time.Time { return base })

	first, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "198.51.100.10", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: base, Hits: 10, WindowSec: 300, RuleID: "r1",
	})
	second, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "198.51.100.10", URI: "/.env", UserAgent: "scanner", Timestamp: base.Add(time.Hour), Hits: 10, WindowSec: 300, RuleID: "r2",
	})

	r1, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: first})
	if err != nil {
		t.Fatalf("first process: %v", err)
	}
	service.SetClock(func() time.Time { return base.Add(time.Hour) })
	r2, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCrowdSecWAF, Event: second})
	if err != nil {
		t.Fatalf("second process: %v", err)
	}

	if !r1.Reported || !r2.Suppressed || r2.SuppressionReason != "abuseipdb_recently_reported" {
		t.Fatalf("unexpected results: first=%+v second=%+v", r1, r2)
	}
	if len(reporter.reports) != 1 {
		t.Fatalf("expected exactly one upstream report, got %d", len(reporter.reports))
	}
}
