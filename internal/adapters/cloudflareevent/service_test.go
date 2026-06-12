package cloudflareevent

import (
	"context"
	"testing"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type fakeSource struct {
	events []cfmodels.WAFEvent
	err    error
}

func (f fakeSource) ListWAFEventsSince(context.Context, string, time.Time) ([]cfmodels.WAFEvent, error) {
	return f.events, f.err
}

type fakeReporter struct {
	reports []abmodels.ExecutableReport
}

func (f *fakeReporter) Execute(_ context.Context, reports []abmodels.ExecutableReport) error {
	f.reports = append(f.reports, reports...)
	return nil
}

type fakeEvidenceStore struct {
	items []reporting.DecisionEvidence
}

func (f *fakeEvidenceStore) Append(_ context.Context, evidence reporting.DecisionEvidence) error {
	f.items = append(f.items, evidence)
	return nil
}

func (f *fakeEvidenceStore) List(_ context.Context, limit int) ([]reporting.DecisionEvidence, error) {
	return f.Search(context.Background(), reporting.EvidenceSearchOptions{Limit: limit})
}

func (f *fakeEvidenceStore) Get(_ context.Context, evidenceID string) (reporting.DecisionEvidence, bool, error) {
	for _, item := range f.items {
		if item.EvidenceID == evidenceID {
			return item, true, nil
		}
	}
	return reporting.DecisionEvidence{}, false, nil
}

func (f *fakeEvidenceStore) Search(_ context.Context, opts reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	out := append([]reporting.DecisionEvidence(nil), f.items...)
	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out, nil
}

func (f *fakeEvidenceStore) Count(_ context.Context, opts reporting.EvidenceSearchOptions) (int, error) {
	out, err := f.Search(context.Background(), reporting.EvidenceSearchOptions{Limit: opts.Limit})
	return len(out), err
}

func TestProcessSinceSuppressesBenignBootstrap(t *testing.T) {
	recorder := &sinks.RecorderSink{}
	reporter := &fakeReporter{}
	reportingService := reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute)
	service := NewService(fakeSource{
		events: []cfmodels.WAFEvent{{
			Action:            "block",
			ClientIP:          "8.8.8.8",
			Datetime:          time.Now().UTC(),
			ClientRequestPath: "/favicon.ico",
			Host:              "arleo.eu",
			Source:            "waf",
			UserAgent:         "",
		}},
	}, reportingService)

	report, err := service.ProcessSince(context.Background(), "zone-id", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("process since: %v", err)
	}
	if report.Reported != 0 || len(reporter.reports) != 0 {
		t.Fatalf("expected no reports, got %+v %+v", report, reporter.reports)
	}
	if len(recorder.Events) != 1 {
		t.Fatalf("expected telemetry event, got %d", len(recorder.Events))
	}
	if recorder.Events[0].SuppressionReason == "" {
		t.Fatal("expected suppression reason")
	}
}

func TestProcessSinceReportsHighConfidenceEvent(t *testing.T) {
	recorder := &sinks.RecorderSink{}
	reporter := &fakeReporter{}
	reportingService := reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute)
	service := NewService(fakeSource{
		events: []cfmodels.WAFEvent{{
			Action:             "block",
			ClientIP:           "8.8.8.8",
			Datetime:           time.Now().UTC(),
			ClientRequestPath:  "/search",
			ClientRequestQuery: "q=union+select+1",
			Host:               "arleo.eu",
			Source:             "waf",
			UserAgent:          "sqlmap/1.0",
			RuleID:             "cf-rule-1",
			Description:        "SQLi rule",
		}},
	}, reportingService)

	report, err := service.ProcessSince(context.Background(), "zone-id", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("process since: %v", err)
	}
	if report.Reported != 1 || len(reporter.reports) != 1 {
		t.Fatalf("expected one report, got report=%+v reports=%+v", report, reporter.reports)
	}
	if reporter.reports[0].Categories != "19,21" && reporter.reports[0].Categories != "21" {
		t.Fatalf("unexpected categories: %s", reporter.reports[0].Categories)
	}
	if len(recorder.Events) != 1 || !recorder.Events[0].AbuseIPDBReported {
		t.Fatalf("expected reported telemetry, got %+v", recorder.Events)
	}
	if report.HighWatermark.IsZero() {
		t.Fatal("expected high watermark to be populated")
	}
}

func TestProcessSinceHandlesMalformedEventTelemetryOnly(t *testing.T) {
	recorder := &sinks.RecorderSink{}
	reporter := &fakeReporter{}
	evidence := &fakeEvidenceStore{}
	reportingService := reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute)
	reportingService.SetEvidenceStore(evidence)
	service := NewService(fakeSource{
		events: []cfmodels.WAFEvent{{
			Action:      "block",
			ClientIP:    "",
			Datetime:    time.Now().UTC(),
			Host:        "arleo.eu",
			Source:      "waf",
			UserAgent:   "",
			RuleID:      "",
			Description: "missing ip",
		}},
	}, reportingService)

	report, err := service.ProcessSince(context.Background(), "zone-id", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("process since: %v", err)
	}
	if report.Reported != 0 || len(reporter.reports) != 0 {
		t.Fatalf("expected no report for malformed event, got %+v", report)
	}
	if len(recorder.Events) != 1 {
		t.Fatalf("expected one telemetry event, got %d", len(recorder.Events))
	}
	if recorder.Events[0].SuppressionReason != "malformed_event" {
		t.Fatalf("unexpected telemetry event: %+v", recorder.Events[0])
	}
	if len(evidence.items) != 1 || evidence.items[0].SuppressionReason != "malformed_event" {
		t.Fatalf("expected malformed event evidence, got %+v", evidence.items)
	}
}

func TestProcessSinceMixedBatchReportsOnceAndSuppressesMalformed(t *testing.T) {
	recorder := &sinks.RecorderSink{}
	reporter := &fakeReporter{}
	reportingService := reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute)
	service := NewService(fakeSource{
		events: []cfmodels.WAFEvent{
			{
				Action:      "block",
				ClientIP:    "",
				Datetime:    time.Now().UTC(),
				Host:        "arleo.eu",
				Source:      "waf",
				Description: "missing ip",
			},
			{
				Action:             "block",
				ClientIP:           "8.8.8.8",
				Datetime:           time.Now().UTC(),
				ClientRequestPath:  "/search",
				ClientRequestQuery: "q=union+select+1",
				Host:               "arleo.eu",
				Source:             "waf",
				UserAgent:          "sqlmap/1.0",
				RuleID:             "cf-rule-1",
				Description:        "SQLi rule",
			},
		},
	}, reportingService)

	report, err := service.ProcessSince(context.Background(), "zone-id", time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("process since: %v", err)
	}
	if report.Fetched != 2 || report.Reported != 1 || report.Suppressed != 1 {
		t.Fatalf("unexpected mixed batch report: %+v", report)
	}
	if len(reporter.reports) != 1 || len(recorder.Events) != 2 {
		t.Fatalf("unexpected side effects: reports=%d events=%d", len(reporter.reports), len(recorder.Events))
	}
	if report.HighWatermark.IsZero() {
		t.Fatal("expected high watermark for mixed batch")
	}
}
