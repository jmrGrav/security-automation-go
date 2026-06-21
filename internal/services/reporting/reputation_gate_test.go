package reporting_test

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

// fakeReputationGate lets tests dictate exactly what decision Process() sees
// without exercising the real enrichment HTTP stack.
type fakeReputationGate struct {
	decision reputation.Decision
	calls    int
}

func (f *fakeReputationGate) EvaluateReport(_ context.Context, _ string, _ reputation.LocalSignal) reputation.Decision {
	f.calls++
	return f.decision
}

func buildExploitEvent(t *testing.T, base time.Time) cloudflareevent.RawEvent {
	t.Helper()
	return cloudflareevent.RawEvent{
		IP:        "9.9.9.9",
		URI:       "/search?q=union+select+1+from+users",
		UserAgent: "sqlmap/1.0",
		Timestamp: base,
		Hits:      1,
		WindowSec: 60,
		RuleID:    "r-exploit",
		Action:    "block",
		Source:    "cloudflare",
		Hostname:  "arleo.eu",
	}
}

func newReportingServiceForGateTest(t *testing.T, base time.Time) (*reporting.Service, *fakeReporter) {
	t.Helper()
	reporter := &fakeReporter{}
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Hour)
	service.SetClock(func() time.Time { return base })
	return service, reporter
}

// Mandatory test: enforce mode -> gate suppression actually blocks the report.
func TestProcess_ReputationGate_EnforceMode_SuppressesReport(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	service, reporter := newReportingServiceForGateTest(t, base)

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:      reputation.ActionSuppressLowConfidence,
		Reason:      reputation.ReasonSuppressedLowReputationConfidence,
		AllowReport: false,
		Shadow:      false, // enforce mode
	}}
	service.SetReputationGate(gate)

	event, err := cloudflareevent.Normalize(buildExploitEvent(t, base))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if gate.calls != 1 {
		t.Fatalf("expected gate to be consulted exactly once, got %d", gate.calls)
	}
	if !result.Suppressed || result.SuppressionReason != reputation.ReasonSuppressedLowReputationConfidence {
		t.Fatalf("expected suppression by reputation gate, got %+v", result)
	}
	if len(reporter.Reports()) != 0 {
		t.Fatalf("expected zero upstream reports, got %d", len(reporter.Reports()))
	}
}

// Mandatory test: shadow mode -> gate decision computed (called) but report
// still proceeds exactly per pre-existing logic — zero side effect from the
// gate itself.
func TestProcess_ReputationGate_ShadowMode_NoSideEffect(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	service, reporter := newReportingServiceForGateTest(t, base)

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:      reputation.ActionSuppressLowConfidence,
		Reason:      reputation.ReasonSuppressedLowReputationConfidence,
		AllowReport: false,
		Shadow:      true, // shadow mode: must not be applied
	}}
	service.SetReputationGate(gate)

	event, err := cloudflareevent.Normalize(buildExploitEvent(t, base))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if gate.calls != 1 {
		t.Fatalf("expected gate to be consulted exactly once, got %d", gate.calls)
	}
	if result.Suppressed {
		t.Fatalf("shadow-mode gate decision must never suppress for real, got %+v", result)
	}
	if !result.Reported {
		t.Fatalf("expected pre-existing logic (report) to proceed untouched in shadow mode, got %+v", result)
	}
	if len(reporter.Reports()) != 1 {
		t.Fatalf("expected exactly one upstream report despite shadow suppression decision, got %d", len(reporter.Reports()))
	}
}

// Mandatory test: nil gate (default) -> behaves exactly like before this
// feature existed — the regression shield.
func TestProcess_ReputationGate_NilGate_NoBehaviorChange(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	service, reporter := newReportingServiceForGateTest(t, base)
	// No SetReputationGate call.

	event, err := cloudflareevent.Normalize(buildExploitEvent(t, base))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Reported {
		t.Fatalf("expected report to proceed with nil gate, got %+v", result)
	}
	if len(reporter.Reports()) != 1 {
		t.Fatalf("expected exactly one upstream report, got %d", len(reporter.Reports()))
	}
}

// Mandatory test: gate allows -> report proceeds normally in enforce mode.
func TestProcess_ReputationGate_EnforceMode_AllowsReport(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	service, reporter := newReportingServiceForGateTest(t, base)

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:      reputation.ActionAllow,
		Reason:      reputation.ReasonAllowedCorroborated,
		AllowReport: true,
		Shadow:      false,
	}}
	service.SetReputationGate(gate)

	event, err := cloudflareevent.Normalize(buildExploitEvent(t, base))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Reported {
		t.Fatalf("expected report to proceed, got %+v", result)
	}
	if len(reporter.Reports()) != 1 {
		t.Fatalf("expected exactly one upstream report, got %d", len(reporter.Reports()))
	}
}

// investigation_shadow: a confirmed-hostile local payload with low AbuseIPDB
// confidence should be suppressed with the investigation_shadow reason, not
// auto-reported, when the gate is in enforce mode.
func TestProcess_ReputationGate_InvestigationShadow_SuppressesAutoReport(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	service, reporter := newReportingServiceForGateTest(t, base)

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:      reputation.ActionInvestigationShadow,
		Reason:      reputation.ReasonInvestigationShadow,
		AllowReport: false,
		Shadow:      false,
	}}
	service.SetReputationGate(gate)

	event, err := cloudflareevent.Normalize(buildExploitEvent(t, base))
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed || result.SuppressionReason != reputation.ReasonInvestigationShadow {
		t.Fatalf("expected investigation_shadow suppression, got %+v", result)
	}
	if len(reporter.Reports()) != 0 {
		t.Fatalf("expected zero upstream reports for investigation_shadow, got %d", len(reporter.Reports()))
	}
}
