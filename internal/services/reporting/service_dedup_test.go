package reporting_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/adapters/openrestyevent"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

func TestDuplicateRecentReportSuppressed(t *testing.T) {
	reporter := &fakeReporter{}
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Hour)
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "8.8.8.8", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: time.Now().UTC(), Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	first, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("first process: %v", err)
	}
	second, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("second process: %v", err)
	}
	if !first.Reported || !second.Suppressed || second.SuppressionReason != "duplicate_report" {
		t.Fatalf("unexpected duplicate behavior: first=%+v second=%+v", first, second)
	}
}

func TestAbuseIPDB24HourPerIPSuppression(t *testing.T) {
	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	store := newFakeDedupStore()
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Hour)
	service.SetReportDedupStore(store)
	service.SetClock(func() time.Time { return base })
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "8.8.8.8", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: base, Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	first, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("first process: %v", err)
	}
	if !first.Reported || store.markCount != 1 {
		t.Fatalf("expected first report to be sent and marked, got %+v markCount=%d", first, store.markCount)
	}

	service.SetClock(func() time.Time { return base.Add(time.Hour) })
	second, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceOpenRestyWAF, Event: event})
	if err != nil {
		t.Fatalf("second process: %v", err)
	}
	if !second.Suppressed || second.SuppressionReason != "abuseipdb_recently_reported" {
		t.Fatalf("expected recent-report suppression, got %+v", second)
	}

	service.SetClock(func() time.Time { return base.Add(23*time.Hour + 59*time.Minute) })
	third, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCrowdSecWAF, Event: event})
	if err != nil {
		t.Fatalf("third process: %v", err)
	}
	if !third.Suppressed || third.SuppressionReason != "abuseipdb_recently_reported" {
		t.Fatalf("expected 23h59 suppression, got %+v", third)
	}

	service.SetClock(func() time.Time { return base.Add(24*time.Hour + time.Minute) })
	fourth, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("fourth process: %v", err)
	}
	if !fourth.Reported || store.markCount != 2 {
		t.Fatalf("expected report after 24h window, got %+v markCount=%d", fourth, store.markCount)
	}
}

func TestAbuseIPDBRecentSuppressionAcrossSourcesAndAbuseTypes(t *testing.T) {
	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	store := newFakeDedupStore()
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportDedupStore(store)
	service.SetClock(func() time.Time { return base })

	exploit, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "9.9.9.9", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: base, Hits: 10, WindowSec: 300, RuleID: "r1",
	})
	if _, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: exploit}); err != nil {
		t.Fatalf("first report: %v", err)
	}

	service.SetClock(func() time.Time { return base.Add(2 * time.Hour) })
	wp, _ := openrestyevent.Normalize(openrestyevent.RawEvent{
		IP: "9.9.9.9", URIs: []string{"/search?q=union+select+1"}, UserAgent: "sqlmap", Timestamp: base.Add(2 * time.Hour), Hits: 10, WindowSec: 300,
	})
	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceOpenRestyWAF, Event: wp})
	if err != nil {
		t.Fatalf("second report: %v", err)
	}
	if !result.Suppressed || result.SuppressionReason != "abuseipdb_recently_reported" {
		t.Fatalf("expected cross-source suppression, got %+v", result)
	}
}

func TestReportFailureDoesNotMarkReported(t *testing.T) {
	base := time.Now().UTC()
	reporter := &fakeReporter{err: errors.New("boom")}
	store := newFakeDedupStore()
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportDedupStore(store)
	service.SetClock(func() time.Time { return base })
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "7.7.7.7", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: base, Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	if _, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event}); err == nil {
		t.Fatal("expected report failure")
	}
	if store.markCount != 0 {
		t.Fatalf("report failure must not mark ip as reported, got %d", store.markCount)
	}
}

func TestStrictReservationFailurePreventsUpstreamReport(t *testing.T) {
	base := time.Now().UTC()
	reporter := &fakeReporter{}
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportReservationStore(&fakeReservationStore{err: errors.New("reservation down")})
	service.SetClock(func() time.Time { return base })
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "7.7.7.8", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: base, Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed || result.SuppressionReason != "abuseipdb_report_reservation_failed" {
		t.Fatalf("expected reservation suppression, got %+v", result)
	}
	if len(reporter.reports) != 0 {
		t.Fatalf("upstream report must not be sent when reservation fails, got %d", len(reporter.reports))
	}
}

func TestStrictEvidenceFailurePreventsUpstreamReport(t *testing.T) {
	base := time.Now().UTC()
	reporter := &fakeReporter{}
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportReservationStore(&fakeReservationStore{})
	service.SetEvidenceStore(&fakeEvidenceStore{err: errors.New("evidence down")})
	service.SetClock(func() time.Time { return base })
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "7.7.7.9", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: base, Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed || result.SuppressionReason != "abuseipdb_report_evidence_failed" {
		t.Fatalf("expected evidence suppression, got %+v", result)
	}
	if len(reporter.reports) != 0 {
		t.Fatalf("upstream report must not be sent when pending evidence fails, got %d", len(reporter.reports))
	}
}

func TestStrictReservationSuccessRecordsPendingAndSucceededEvidence(t *testing.T) {
	base := time.Now().UTC()
	reporter := &fakeReporter{}
	evidence := &fakeEvidenceStore{}
	reservations := &fakeReservationStore{}
	store := newFakeDedupStore()
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportReservationStore(reservations)
	service.SetEvidenceStore(evidence)
	service.SetReportDedupStore(store)
	service.SetClock(func() time.Time { return base })
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "7.7.7.10", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: base, Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Reported || len(reporter.reports) != 1 || store.markCount != 1 {
		t.Fatalf("expected reported result, reports=%d marks=%d result=%+v", len(reporter.reports), store.markCount, result)
	}
	if len(evidence.evidence) < 2 {
		t.Fatalf("expected pending and success evidence, got %d", len(evidence.evidence))
	}
	if reservations.statuses[reservations.reserve[0].EvidenceID] != reporting.ReportStatusReported {
		t.Fatalf("expected reported reservation status, got %#v", reservations.statuses)
	}
}

func TestDedupStoreErrorFailClosedByDefault(t *testing.T) {
	service := reporting.New(&fakeReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportDedupStore(&fakeDedupStore{err: errors.New("store down"), last: make(map[string]time.Time)})
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "6.6.6.6", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: time.Now().UTC(), Hits: 10, WindowSec: 300, RuleID: "r1",
	})
	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed || result.SuppressionReason != "abuseipdb_dedup_store_error" {
		t.Fatalf("expected fail-closed suppression on store error, got %+v", result)
	}
}

func TestConcurrentReportsSameIPOnlyOneSent(t *testing.T) {
	base := time.Now().UTC()
	reporter := &fakeReporter{}
	store := newFakeDedupStore()
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportDedupStore(store)
	service.SetClock(func() time.Time { return base })
	event, _ := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP: "5.5.5.5", URI: "/search?q=union+select+1", UserAgent: "sqlmap", Timestamp: base, Hits: 10, WindowSec: 300, RuleID: "r1",
	})

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
		}()
	}
	wg.Wait()

	if len(reporter.reports) != 1 {
		t.Fatalf("expected exactly one report sent, got %d", len(reporter.reports))
	}
}
