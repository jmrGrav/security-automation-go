package reporting_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/events"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

// TestOperatorProtectedIPIsNeverReported verifies that an IP added to the trust
// registry as an operator-protected host is suppressed with "protected_target"
// and never forwarded to the upstream AbuseIPDB reporter.
func TestOperatorProtectedIPIsNeverReported(t *testing.T) {
	const operatorIP = "82.65.145.189"
	base := time.Date(2026, 6, 13, 10, 0, 0, 0, time.UTC)

	reg := trust.DefaultRegistry()
	reg.Add(trust.ProtectedResource{
		Name:             "operator-host-" + operatorIP,
		Kind:             "host",
		CIDR:             operatorIP + "/32",
		Tags:             []string{"operator", "protected"},
		MinConfidence:    1.0,
		AllowPropagation: false,
	})

	reporter := &fakeReporter{}
	svc := reporting.New(reporter, &sinks.RecorderSink{}, reg, time.Minute)
	svc.SetClock(func() time.Time { return base })

	event, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP:        operatorIP,
		URI:       "/admin",
		UserAgent: "Mozilla/5.0",
		Timestamp: base,
		Hits:      5,
		WindowSec: 300,
		RuleID:    "block-001",
		Action:    "block",
		Source:    "cloudflare",
		Hostname:  "example.com",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}

	result, err := svc.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Suppressed {
		t.Fatalf("expected operator IP to be suppressed, got %+v", result)
	}
	if result.SuppressionReason != "protected_target" {
		t.Fatalf("expected suppression reason 'protected_target', got %q", result.SuppressionReason)
	}
	if result.Reported {
		t.Fatal("operator IP must never be reported to AbuseIPDB")
	}
	if len(reporter.Reports()) != 0 {
		t.Fatalf("expected zero upstream calls for operator IP, got %d", len(reporter.Reports()))
	}

	// Unrelated IP must still be reportable (regression guard).
	otherEvent, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP:        "1.2.3.4",
		URI:       "/wp-login.php",
		UserAgent: "sqlmap",
		Timestamp: base,
		Hits:      10,
		WindowSec: 300,
		RuleID:    "block-002",
		Action:    "block",
		Source:    "cloudflare",
		Hostname:  "example.com",
	})
	if err != nil {
		t.Fatalf("normalize other: %v", err)
	}
	otherResult, err := svc.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: otherEvent})
	if err != nil {
		t.Fatalf("process other: %v", err)
	}
	if !otherResult.Reported {
		t.Fatalf("non-protected IP should be reportable, got suppressed=%v reason=%q", otherResult.Suppressed, otherResult.SuppressionReason)
	}
}

func TestReplayHashWrappersAreStableAndDistinct(t *testing.T) {
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
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
	req := reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event}
	cls := classifier.Classify(event)

	inputHash1 := reporting.ReplayInputHash(req)
	inputHash2 := reporting.ReplayInputHash(req)
	if inputHash1 != inputHash2 {
		t.Fatalf("input hash must be stable, got %q and %q", inputHash1, inputHash2)
	}
	if other := reporting.ReplayInputHash(reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: withURIs(event, []string{"/other"})}); other == inputHash1 {
		t.Fatal("input hash must change when the logical input changes")
	}

	decisionHash1 := reporting.ReplayDecisionHash("canonical comment", cls, "reported", "")
	decisionHash2 := reporting.ReplayDecisionHash("canonical comment", cls, "reported", "")
	if decisionHash1 != decisionHash2 {
		t.Fatalf("decision hash must be stable, got %q and %q", decisionHash1, decisionHash2)
	}
	if other := reporting.ReplayDecisionHash("different comment", cls, "reported", ""); other == decisionHash1 {
		t.Fatal("decision hash must change when the decision payload changes")
	}
}

func TestSetReportWindowControlsRecentSuppression(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	dedup := newFakeDedupStore()
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportDedupStore(dedup)
	service.SetClock(func() time.Time { return base })
	service.SetReportWindow(10 * time.Minute)

	event, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP:        "8.8.4.4",
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
	if !first.Reported {
		t.Fatalf("expected first event to report, got %+v", first)
	}

	service.SetClock(func() time.Time { return base.Add(9 * time.Minute) })
	second, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("second process: %v", err)
	}
	if !second.Suppressed || second.SuppressionReason != "abuseipdb_recently_reported" {
		t.Fatalf("expected recent suppression inside window, got %+v", second)
	}

	service.SetClock(func() time.Time { return base.Add(11 * time.Minute) })
	third, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("third process: %v", err)
	}
	if !third.Reported {
		t.Fatalf("expected report after window expires, got %+v", third)
	}
}

func TestSetFailClosedOnStoreErrorAllowsReportWhenDisabled(t *testing.T) {
	base := time.Date(2026, 6, 1, 13, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	dedup := newFakeDedupStore()
	dedup.err = errors.New("dedup store down")
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportDedupStore(dedup)
	service.SetFailClosedOnStoreError(false)
	service.SetClock(func() time.Time { return base })

	event, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP:        "9.9.9.9",
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

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Reported {
		t.Fatalf("expected report to proceed when dedup store error is non-fatal, got %+v", result)
	}
	if len(reporter.Reports()) != 1 {
		t.Fatalf("expected upstream report, got %d calls", len(reporter.Reports()))
	}
}

func TestObservePersistsObservedEvidence(t *testing.T) {
	base := time.Date(2026, 6, 1, 14, 0, 0, 0, time.UTC)
	recorder := &sinks.RecorderSink{}
	evidence := &fakeEvidenceStore{}
	service := reporting.New(&fakeReporter{}, recorder, trust.DefaultRegistry(), time.Minute)
	service.SetEvidenceStore(evidence)
	service.SetClock(func() time.Time { return base })

	event := events.SecurityEvent{
		Timestamp:        base,
		Source:           "cloudflare_waf",
		IP:               "10.10.10.10",
		URI:              "/admin",
		Hostname:         "arleo.eu",
		RuleID:           "rule-1",
		AbuseType:        "confirmed_abuse",
		RiskScore:        21,
		Confidence:       0.97,
		EnforcementStage: "propagable_ban",
		Metadata:         map[string]any{"note": "observed"},
	}

	service.Observe(context.Background(), event)

	if len(recorder.Events) != 1 {
		t.Fatalf("expected telemetry publish, got %d events", len(recorder.Events))
	}
	got := evidence.Evidence()
	if len(got) != 1 {
		t.Fatalf("expected observed evidence append, got %d entries", len(got))
	}
	if got[0].Decision != "observed" || got[0].EvidenceID == "" {
		t.Fatalf("unexpected observed evidence: %+v", got[0])
	}
}

func TestFinalizeReportedDecisionRecordsDedupFailureButKeepsReported(t *testing.T) {
	base := time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)
	reporter := &fakeReporter{}
	dedup := &fakeDedupStore{markErr: errors.New("mark failed")}
	reservations := &fakeReservationStore{}
	evidence := &fakeEvidenceStore{}
	service := reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
	service.SetReportDedupStore(dedup)
	service.SetReportReservationStore(reservations)
	service.SetEvidenceStore(evidence)
	service.SetClock(func() time.Time { return base })

	event, err := cloudflareevent.Normalize(cloudflareevent.RawEvent{
		IP:        "11.11.11.11",
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

	result, err := service.Process(context.Background(), reporting.Request{Source: abuseformat.SourceCloudflareWAF, Event: event})
	if err != nil {
		t.Fatalf("process: %v", err)
	}
	if !result.Reported {
		t.Fatalf("expected reported result despite dedup mark error, got %+v", result)
	}
	if result.TelemetryEvent.Metadata["dedup_store_mark_error"] == "" {
		t.Fatalf("expected dedup mark error metadata, got %+v", result.TelemetryEvent.Metadata)
	}
	if reservations.statuses == nil || reservations.statuses[reservations.reserve[0].EvidenceID] != reporting.ReportStatusReportedDedupFailed {
		t.Fatalf("expected dedup-failed reservation status, got %+v", reservations.statuses)
	}
}
