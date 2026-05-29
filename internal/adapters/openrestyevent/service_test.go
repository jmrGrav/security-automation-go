package openrestyevent

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

func TestServiceUsesUnifiedReportingPipeline(t *testing.T) {
	reporter := &fakeReporter{}
	recorder := &sinks.RecorderSink{}
	service := NewService(reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute))

	result, err := service.Process(context.Background(), RawEvent{
		IP:        "8.8.8.8",
		Hostname:  "arleo.eu",
		URIs:      []string{"/wp-login.php", "/xmlrpc.php"},
		Action:    "block",
		RuleID:    "openresty-rule",
		RuleName:  "wordpress",
		Timestamp: time.Now().UTC(),
		Hits:      9,
		WindowSec: 300,
	})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if result.Comment == "" {
		t.Fatal("expected canonical comment")
	}
	if len(recorder.Events) != 1 {
		t.Fatalf("expected telemetry event, got %d", len(recorder.Events))
	}
}
