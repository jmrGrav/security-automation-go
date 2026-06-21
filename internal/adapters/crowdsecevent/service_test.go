package crowdsecevent

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
		RuleID:    "crowdsec-rule",
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

// A detection-only WAF event (action="detected", i.e. no CrowdSec ban
// decision attached) must never reach AbuseIPDB/Spamhaus — it must be
// recorded as evidence only.
func TestServiceMarksDetectionOnlyEventsEvidenceOnly(t *testing.T) {
	reporter := &fakeReporter{}
	recorder := &sinks.RecorderSink{}
	service := NewService(reporting.New(reporter, recorder, trust.DefaultRegistry(), time.Minute))

	result, err := service.Process(context.Background(), RawEvent{
		IP:        "194.126.177.86",
		Hostname:  "www.arleo.eu",
		URIs:      []string{"/?q=%3Cscript%3Ealert(1)%3C/script%3E%22"},
		Action:    "detected",
		RuleID:    "native_rule:941100",
		RuleName:  "XSS Attack Detected via libinjection",
		Timestamp: time.Now().UTC(),
		Hits:      1,
		WindowSec: 300,
	})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed || result.SuppressionReason != "waf_evidence_only" {
		t.Fatalf("expected evidence-only suppression, got suppressed=%v reason=%q", result.Suppressed, result.SuppressionReason)
	}
	if len(reporter.reports) != 0 {
		t.Fatalf("detection-only event must never be reported upstream, got %d reports", len(reporter.reports))
	}
}
