package sqlite

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type captureReporter struct {
	reports []abmodels.ExecutableReport
}

func (c *captureReporter) Execute(_ context.Context, reports []abmodels.ExecutableReport) error {
	c.reports = append(c.reports, reports...)
	return nil
}

func (c *captureReporter) Reports() []abmodels.ExecutableReport {
	return append([]abmodels.ExecutableReport(nil), c.reports...)
}

type failingEvidenceStore struct {
	err error
}

func (f failingEvidenceStore) Append(context.Context, reporting.DecisionEvidence) error {
	return f.err
}

func (f failingEvidenceStore) List(context.Context, int) ([]reporting.DecisionEvidence, error) {
	return nil, f.err
}

func (f failingEvidenceStore) Get(context.Context, string) (reporting.DecisionEvidence, bool, error) {
	return reporting.DecisionEvidence{}, false, f.err
}

func (f failingEvidenceStore) Search(context.Context, reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	return nil, f.err
}

func (f failingEvidenceStore) Count(context.Context, reporting.EvidenceSearchOptions) (int, error) {
	return 0, f.err
}

func TestAbuseIPDBAggregationWindowProtectedAndEvidenceFailure(t *testing.T) {
	t.Run("aggregates same ip inside 30s", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatalf("sqlite new: %v", err)
		}
		defer db.Close()

		stores := NewReportingStores(db)
		reporter := &captureReporter{}
		service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
		stores.Configure(service)

		base := time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC)
		current := base
		clock := func() time.Time { return current }
		stores.Outbox.now = clock
		service.SetClock(clock)
		service.SetReportWindow(30 * time.Second)

		first := mustCloudflareEvent(t, cloudflareevent.RawEvent{
			IP:        "8.8.8.8",
			URI:       "/wp-login.php",
			UserAgent: "sqlmap",
			Timestamp: base,
			Hits:      10,
			WindowSec: 300,
			RuleID:    "r1",
			Action:    "block",
			Source:    "cloudflare",
			Hostname:  "arleo.eu",
		})
		second := mustCloudflareEvent(t, cloudflareevent.RawEvent{
			IP:        "8.8.8.8",
			URI:       "/xmlrpc.php",
			UserAgent: "sqlmap",
			Timestamp: base.Add(15 * time.Second),
			Hits:      10,
			WindowSec: 300,
			RuleID:    "r2",
			Action:    "block",
			Source:    "cloudflare",
			Hostname:  "arleo.eu",
		})

		for _, event := range []struct {
			ev  classifier.Event
			uri string
		}{{first, "/wp-login.php"}, {second, "/xmlrpc.php"}} {
			result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event.ev})
			if err != nil {
				t.Fatalf("process %s: %v", event.uri, err)
			}
			if !result.Suppressed || result.SuppressionReason != "report_pending" {
				t.Fatalf("expected pending reservation for %s, got %+v", event.uri, result)
			}
		}

		var pendingRows int
		if err := db.Conn().QueryRowContext(context.Background(), `
			SELECT count(*) FROM abuseipdb_report_outbox WHERE status = ?
		`, reporting.ReportStatusPending).Scan(&pendingRows); err != nil {
			t.Fatalf("count pending: %v", err)
		}
		if pendingRows != 1 {
			t.Fatalf("expected one aggregated pending row, got %d", pendingRows)
		}

		var reportJSON string
		if err := db.Conn().QueryRowContext(context.Background(), `
			SELECT report_json FROM abuseipdb_report_outbox
			WHERE status = ?
			ORDER BY created_at DESC
			LIMIT 1
		`, reporting.ReportStatusPending).Scan(&reportJSON); err != nil {
			t.Fatalf("query report json: %v", err)
		}
		var merged abmodels.ExecutableReport
		if err := json.Unmarshal([]byte(reportJSON), &merged); err != nil {
			t.Fatalf("unmarshal report: %v", err)
		}
		if merged.Hits != 20 {
			t.Fatalf("expected merged hits 20, got %d", merged.Hits)
		}
		if !strings.Contains(merged.Comment, "20 hits in 30s") {
			t.Fatalf("expected aggregated 30s comment, got %q", merged.Comment)
		}
		if len(merged.URIs) != 2 {
			t.Fatalf("expected merged URIs, got %+v", merged.URIs)
		}

		current = base.Add(31 * time.Second)
		service.SetClock(clock)
		worker := reporting.NewOutboxWorker(stores.Outbox, reporter, stores.Dedup, stores.Evidence, &sinks.RecorderSink{}, reporting.OutboxWorkerConfig{
			Clock:      func() time.Time { return current },
			Limit:      1,
			ClaimLease: 5 * time.Second,
		})
		processed, err := worker.ProcessOnce(context.Background())
		if err != nil {
			t.Fatalf("outbox process: %v", err)
		}
		if processed != 1 {
			t.Fatalf("expected one outbox item, got %d", processed)
		}
		reports := reporter.Reports()
		if len(reports) != 1 {
			t.Fatalf("expected one upstream report, got %d", len(reports))
		}
		if reports[0].Hits != 20 {
			t.Fatalf("expected upstream report hits 20, got %d", reports[0].Hits)
		}

		third := mustCloudflareEvent(t, cloudflareevent.RawEvent{
			IP:        "8.8.8.8",
			URI:       "/admin",
			UserAgent: "sqlmap",
			Timestamp: base.Add(61 * time.Second),
			Hits:      10,
			WindowSec: 300,
			RuleID:    "r3",
			Action:    "block",
			Source:    "cloudflare",
			Hostname:  "arleo.eu",
		})
		current = base.Add(61 * time.Second)
		service.SetClock(clock)
		result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: third})
		if err != nil {
			t.Fatalf("process new window: %v", err)
		}
		if !result.Suppressed || result.SuppressionReason != "report_pending" {
			t.Fatalf("expected pending reservation for new window, got %+v", result)
		}
		current = base.Add(92 * time.Second)
		service.SetClock(clock)
		processed, err = worker.ProcessOnce(context.Background())
		if err != nil {
			t.Fatalf("second outbox process: %v", err)
		}
		if processed != 1 {
			t.Fatalf("expected second outbox item, got %d", processed)
		}
		if len(reporter.Reports()) != 2 {
			t.Fatalf("expected two upstream reports across windows, got %d", len(reporter.Reports()))
		}
		if reporter.Reports()[1].Hits != 10 {
			t.Fatalf("expected second-window report hits 10, got %d", reporter.Reports()[1].Hits)
		}
	})

	t.Run("protected ip is suppressed before reporting", func(t *testing.T) {
		reg := trust.DefaultRegistry()
		reg.Add(trust.ProtectedResource{
			Name:             "operator-host-82.65.145.189",
			Kind:             "host",
			CIDR:             "82.65.145.189/32",
			Tags:             []string{"operator", "protected"},
			MinConfidence:    1.0,
			AllowPropagation: false,
		})
		service := reporting.New(&captureReporter{}, &sinks.RecorderSink{}, reg, time.Minute)
		event := mustCloudflareEvent(t, cloudflareevent.RawEvent{
			IP:        "82.65.145.189",
			URI:       "/admin",
			UserAgent: "Mozilla/5.0",
			Timestamp: time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC),
			Hits:      5,
			WindowSec: 300,
			RuleID:    "protected",
			Action:    "block",
			Source:    "cloudflare",
			Hostname:  "arleo.eu",
		})
		result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
		if err != nil {
			t.Fatalf("process protected: %v", err)
		}
		if !result.Suppressed || result.SuppressionReason != "protected_target" {
			t.Fatalf("expected protected suppression, got %+v", result)
		}
	})

	t.Run("evidence failure maps to dedicated suppression", func(t *testing.T) {
		db, err := New(t.TempDir())
		if err != nil {
			t.Fatalf("sqlite new: %v", err)
		}
		defer db.Close()

		stores := NewReportingStores(db)
		service := reporting.New(&captureReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
		stores.Configure(service)
		service.SetEvidenceStore(failingEvidenceStore{err: errors.New("evidence down")})
		clock := func() time.Time { return time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC) }
		stores.Outbox.now = clock
		service.SetClock(clock)
		event := mustCloudflareEvent(t, cloudflareevent.RawEvent{
			IP:        "7.7.7.7",
			URI:       "/search?q=union+select+1",
			UserAgent: "sqlmap",
			Timestamp: time.Date(2026, 6, 13, 12, 0, 0, 0, time.UTC),
			Hits:      10,
			WindowSec: 300,
			RuleID:    "r1",
			Action:    "block",
			Source:    "cloudflare",
			Hostname:  "arleo.eu",
		})
		result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
		if err != nil {
			t.Fatalf("process evidence failure: %v", err)
		}
		if !result.Suppressed || result.SuppressionReason != "abuseipdb_report_evidence_failed" {
			t.Fatalf("expected evidence failure suppression, got %+v", result)
		}
	})
}

func mustCloudflareEvent(t *testing.T, raw cloudflareevent.RawEvent) classifier.Event {
	t.Helper()
	event, err := cloudflareevent.Normalize(raw)
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	return event
}
