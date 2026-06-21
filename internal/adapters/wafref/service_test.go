package wafref

import (
	"context"
	"testing"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

type fakeReporter struct {
	reports []abmodels.ExecutableReport
}

func (f *fakeReporter) Execute(_ context.Context, reports []abmodels.ExecutableReport) error {
	f.reports = append(f.reports, reports...)
	return nil
}

func TestServiceRecordsEvidenceOnlyAndNeverReports(t *testing.T) {
	reporter := &fakeReporter{}
	recorder := &sinks.RecorderSink{}
	service := NewService(reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute))

	result, err := service.Process(context.Background(), RawEvent{
		Ref:       "1A2B3C-DEF012",
		Timestamp: time.Now().UTC(),
		IP:        "8.8.8.8",
		Host:      "arleo.eu",
		Method:    "GET",
		URI:       "/?q=<script>alert(1)</script>",
		Reason:    "appsec",
	})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if result.Reported {
		t.Fatal("a waf ref must never be reported upstream")
	}
	if !result.Suppressed {
		t.Fatal("expected the evidence-only suppression path")
	}
	if len(reporter.reports) != 0 {
		t.Fatalf("expected no upstream reports, got %d", len(reporter.reports))
	}
}

func TestServicePropagatesNormalizeError(t *testing.T) {
	reporter := &fakeReporter{}
	recorder := &sinks.RecorderSink{}
	service := NewService(reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute))

	if _, err := service.Process(context.Background(), RawEvent{Ref: "REF1"}); err == nil {
		t.Fatal("expected normalize error for missing ip")
	}
}
