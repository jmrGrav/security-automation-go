package nginxerrors

import (
	"context"
	"net/netip"
	"testing"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/autoban"
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

type fakeErrorSource struct {
	events []RawEvent
	err    error
}

func (f fakeErrorSource) ListErrorsSince(context.Context, time.Time) ([]RawEvent, error) {
	return f.events, f.err
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("parse addr %q: %v", s, err)
	}
	return addr
}

func TestProcessSinceSuppressesBelowMinBurst(t *testing.T) {
	ip := mustAddr(t, "1.2.3.4")
	reporter := &fakeReporter{}
	svc := NewService(fakeErrorSource{events: []RawEvent{
		{IP: ip, Timestamp: time.Now().UTC(), URI: "/missing", Status: 404},
	}}, reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute))

	report, err := svc.ProcessSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("ProcessSince: %v", err)
	}
	if report.Bursts != 0 || report.BelowMinBurst != 1 {
		t.Fatalf("expected single hit to stay below min burst, got %+v", report)
	}
	if len(reporter.reports) != 0 {
		t.Fatalf("expected no upstream reports, got %d", len(reporter.reports))
	}
}

func TestProcessSinceRecordsEvidenceOnlyForQualifyingBurst(t *testing.T) {
	ip := mustAddr(t, "1.2.3.4")
	reporter := &fakeReporter{}
	base := time.Now().UTC()
	events := make([]RawEvent, 0, DefaultMinBurst)
	for i := 0; i < DefaultMinBurst; i++ {
		events = append(events, RawEvent{IP: ip, Timestamp: base.Add(time.Duration(i) * time.Second), URI: "/admin", Status: 404})
	}
	svc := NewService(fakeErrorSource{events: events}, reporting.New(reporter, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute))

	report, err := svc.ProcessSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("ProcessSince: %v", err)
	}
	if report.Bursts != 1 {
		t.Fatalf("expected exactly one qualifying burst, got %+v", report)
	}
	if report.Reported != 0 {
		t.Fatal("an http error burst must never be reported upstream from this path")
	}
	if len(reporter.reports) != 0 {
		t.Fatalf("expected no upstream reports, got %d", len(reporter.reports))
	}
	if !report.HighWatermark.Equal(events[len(events)-1].Timestamp) {
		t.Fatalf("expected high watermark to track the latest event, got %s", report.HighWatermark)
	}
}

func TestProcessSinceSeparatesBurstsByStatusAndIP(t *testing.T) {
	ipA := mustAddr(t, "1.2.3.4")
	ipB := mustAddr(t, "5.6.7.8")
	base := time.Now().UTC()
	events := []RawEvent{
		{IP: ipA, Timestamp: base, URI: "/a", Status: 404},
		{IP: ipA, Timestamp: base.Add(time.Second), URI: "/a", Status: 500},
		{IP: ipB, Timestamp: base, URI: "/a", Status: 404},
	}
	svc := NewService(fakeErrorSource{events: events}, reporting.New(&fakeReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute))
	svc.SetMinBurst(1)

	report, err := svc.ProcessSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("ProcessSince: %v", err)
	}
	if report.Bursts != 3 {
		t.Fatalf("expected 3 distinct ip+status bursts, got %d", report.Bursts)
	}
}

func TestSetMinBurstIgnoresNonPositive(t *testing.T) {
	svc := NewService(fakeErrorSource{}, reporting.New(&fakeReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute))
	svc.SetMinBurst(0)
	if svc.minBurst != DefaultMinBurst {
		t.Fatalf("expected minBurst to stay at default, got %d", svc.minBurst)
	}
	svc.SetMinBurst(-1)
	if svc.minBurst != DefaultMinBurst {
		t.Fatalf("expected minBurst to stay at default, got %d", svc.minBurst)
	}
}

// --- SetEnforcement tests ---

type fakeBanEvaluator struct {
	shadow    bool
	skip      string
	decisions []autoban.BanDecision
	banned    []string
}

func (f *fakeBanEvaluator) EvaluateExternalBurst(ip, reason string) autoban.BanDecision {
	if f.skip != "" {
		return autoban.BanDecision{IP: ip, SkipReason: f.skip}
	}
	return autoban.BanDecision{IP: ip, ShouldBan: true, Reason: reason, Shadow: f.shadow}
}

func (f *fakeBanEvaluator) Log(decision autoban.BanDecision) {
	f.decisions = append(f.decisions, decision)
}

func (f *fakeBanEvaluator) RecordBan(ip string) {
	f.banned = append(f.banned, ip)
}

type fakeBanExecutor struct {
	executed []string
	err      error
}

func (f *fakeBanExecutor) ExecuteBan(_ context.Context, decision autoban.BanDecision) error {
	if f.err != nil {
		return f.err
	}
	f.executed = append(f.executed, decision.IP)
	return nil
}

func newReportingService() *reporting.Service {
	return reporting.New(&fakeReporter{}, &sinks.RecorderSink{}, trust.DefaultRegistry(), time.Minute)
}

func TestSetEnforcementBansWhenThresholdMetAndLive(t *testing.T) {
	ip := mustAddr(t, "9.9.9.9")
	base := time.Now().UTC()
	events := make([]RawEvent, 0, 5)
	for i := 0; i < 5; i++ {
		events = append(events, RawEvent{IP: ip, Timestamp: base.Add(time.Duration(i) * time.Second), URI: "/admin", Status: 404})
	}
	svc := NewService(fakeErrorSource{events: events}, newReportingService())
	svc.SetMinBurst(1)
	evalr := &fakeBanEvaluator{shadow: false}
	exec := &fakeBanExecutor{}
	svc.SetEnforcement(evalr, exec, 5)

	report, err := svc.ProcessSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("ProcessSince: %v", err)
	}
	if report.Banned != 1 {
		t.Fatalf("expected exactly one ban, got %+v", report)
	}
	if len(exec.executed) != 1 || exec.executed[0] != "9.9.9.9" {
		t.Fatalf("expected ban executor to be called for 9.9.9.9, got %v", exec.executed)
	}
	if len(evalr.banned) != 1 {
		t.Fatalf("expected RecordBan to be called once, got %v", evalr.banned)
	}
}

func TestSetEnforcementNeverBansBelowThreshold(t *testing.T) {
	ip := mustAddr(t, "9.9.9.9")
	base := time.Now().UTC()
	events := []RawEvent{
		{IP: ip, Timestamp: base, URI: "/admin", Status: 404},
		{IP: ip, Timestamp: base.Add(time.Second), URI: "/admin", Status: 404},
	}
	svc := NewService(fakeErrorSource{events: events}, newReportingService())
	svc.SetMinBurst(1)
	evalr := &fakeBanEvaluator{shadow: false}
	exec := &fakeBanExecutor{}
	svc.SetEnforcement(evalr, exec, 5) // burst count (2) never reaches threshold (5)

	report, err := svc.ProcessSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("ProcessSince: %v", err)
	}
	if report.Banned != 0 || len(exec.executed) != 0 {
		t.Fatalf("expected no ban below threshold, got report=%+v executed=%v", report, exec.executed)
	}
}

func TestSetEnforcementShadowModeNeverExecutesBan(t *testing.T) {
	ip := mustAddr(t, "9.9.9.9")
	base := time.Now().UTC()
	events := make([]RawEvent, 0, 5)
	for i := 0; i < 5; i++ {
		events = append(events, RawEvent{IP: ip, Timestamp: base.Add(time.Duration(i) * time.Second), URI: "/admin", Status: 404})
	}
	svc := NewService(fakeErrorSource{events: events}, newReportingService())
	svc.SetMinBurst(1)
	evalr := &fakeBanEvaluator{shadow: true} // evaluator running in shadow mode
	exec := &fakeBanExecutor{}
	svc.SetEnforcement(evalr, exec, 5)

	report, err := svc.ProcessSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("ProcessSince: %v", err)
	}
	if report.Banned != 0 || len(exec.executed) != 0 {
		t.Fatalf("expected shadow decisions to never reach the ban executor, got report=%+v executed=%v", report, exec.executed)
	}
}

func TestSetEnforcementNeverBansProtectedOrSkippedIP(t *testing.T) {
	ip := mustAddr(t, "9.9.9.9")
	base := time.Now().UTC()
	events := make([]RawEvent, 0, 5)
	for i := 0; i < 5; i++ {
		events = append(events, RawEvent{IP: ip, Timestamp: base.Add(time.Duration(i) * time.Second), URI: "/admin", Status: 404})
	}
	svc := NewService(fakeErrorSource{events: events}, newReportingService())
	svc.SetMinBurst(1)
	evalr := &fakeBanEvaluator{skip: "protected_target"}
	exec := &fakeBanExecutor{}
	svc.SetEnforcement(evalr, exec, 5)

	report, err := svc.ProcessSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("ProcessSince: %v", err)
	}
	if report.Banned != 0 || len(exec.executed) != 0 {
		t.Fatalf("expected no ban when evaluator skips the IP, got report=%+v executed=%v", report, exec.executed)
	}
}

func TestSetEnforcementNoOpWithThresholdOne(t *testing.T) {
	svc := NewService(fakeErrorSource{}, newReportingService())
	evalr := &fakeBanEvaluator{}
	exec := &fakeBanExecutor{}
	svc.SetEnforcement(evalr, exec, 1) // <= 1 must be rejected: never ban on a single error
	if svc.enforce {
		t.Fatal("expected SetEnforcement to reject banThreshold <= 1")
	}
}

func TestSetEnforcementNoOpWithNilEvaluator(t *testing.T) {
	svc := NewService(fakeErrorSource{}, newReportingService())
	svc.SetEnforcement(nil, &fakeBanExecutor{}, 5)
	if svc.enforce {
		t.Fatal("expected SetEnforcement to no-op with a nil evaluator")
	}
}

func TestProcessSinceNilSafety(t *testing.T) {
	var svc *Service
	report, err := svc.ProcessSince(context.Background(), time.Time{})
	if err != nil {
		t.Fatalf("expected nil-safe no-op, got err=%v", err)
	}
	if report.Fetched != 0 {
		t.Fatalf("expected zero-value report, got %+v", report)
	}
}
