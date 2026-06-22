package autoban_test

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/security/quota"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/autoban"
)

// --- fake enricher ---

type fakeEnricher struct {
	abuseScore int
	err        error
	callCount  int
}

func (f *fakeEnricher) Enrich(_ context.Context, _ netip.Addr, _ enrichment.LookupOptions) (enrichment.EnrichmentSummary, error) {
	f.callCount++
	if f.err != nil {
		return enrichment.EnrichmentSummary{}, f.err
	}
	return enrichment.EnrichmentSummary{
		Providers: []enrichment.ProviderVerdict{
			{Provider: "abuseipdb", Score: f.abuseScore, Manual: true},
		},
	}, nil
}

func newEval(t *testing.T, live bool, enricher autoban.IPEnricher) *autoban.Evaluator {
	t.Helper()
	return autoban.NewEvaluator(
		autoban.Config{LiveMode: live},
		trust.DefaultRegistry(),
		enricher,
		nil,
	)
}

// withLocalEvent records one malicious event so EvaluateConfidence passes the
// local-evidence gate. Call before any EvaluateConfidence call that must reach
// the score check.
func withLocalEvent(t *testing.T, ev *autoban.Evaluator, ip string) {
	t.Helper()
	ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: time.Now()})
}

// --- confidence-100 tests ---

func TestConfidence100_TriggersBanInLiveMode(t *testing.T) {
	const ip = "5.6.7.8"
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	withLocalEvent(t, ev, ip)
	d := ev.EvaluateConfidence(context.Background(), ip)
	if !d.ShouldBan {
		t.Fatalf("expected ban decision, got SkipReason=%q", d.SkipReason)
	}
	if d.Reason != "confidence_100" {
		t.Errorf("expected reason confidence_100, got %q", d.Reason)
	}
	if d.Shadow {
		t.Error("expected Shadow=false in live mode")
	}
}

func TestConfidence100_ShadowModeNeverMutates(t *testing.T) {
	const ip = "5.6.7.8"
	ev := newEval(t, false, &fakeEnricher{abuseScore: 100})
	withLocalEvent(t, ev, ip)
	d := ev.EvaluateConfidence(context.Background(), ip)
	if !d.ShouldBan {
		t.Fatalf("expected ban decision, got SkipReason=%q", d.SkipReason)
	}
	if !d.Shadow {
		t.Error("expected Shadow=true in shadow mode")
	}
}

func TestConfidence100_NoLocalEvidence_Noban(t *testing.T) {
	// confidence=100 from AbuseIPDB but no locally observed events → no ban, no AbuseIPDB call.
	fe := &fakeEnricher{abuseScore: 100}
	ev := newEval(t, true, fe)
	d := ev.EvaluateConfidence(context.Background(), "5.6.7.8")
	if d.ShouldBan {
		t.Fatal("expected no ban without local evidence, got ShouldBan=true")
	}
	if d.SkipReason != "no_local_evidence" {
		t.Errorf("expected skip reason no_local_evidence, got %q", d.SkipReason)
	}
	if fe.callCount != 0 {
		t.Errorf("expected AbuseIPDB Enrich not called, got callCount=%d", fe.callCount)
	}
}

// TestLog_BanDecision_SurfacesCorroboration guards against an operator-facing
// regression: the "autoban: ban decision" log line must surface the
// confidence score and local-evidence corroboration explicitly, so an auditor
// can confirm from the log alone that confidence=100 was never sufficient by
// itself (see internal/services/autoban/evaluator.go's package doc and
// EvaluateConfidence's HasLocalEvidence gate).
func TestLog_BanDecision_SurfacesCorroboration(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	ev := autoban.NewEvaluator(autoban.Config{LiveMode: true}, trust.DefaultRegistry(), &fakeEnricher{abuseScore: 100}, logger)

	const ip = "5.6.7.8"
	withLocalEvent(t, ev, ip)
	d := ev.EvaluateConfidence(context.Background(), ip)
	if !d.ShouldBan {
		t.Fatalf("expected ban decision, got SkipReason=%q", d.SkipReason)
	}
	ev.Log(d)

	out := buf.String()
	for _, want := range []string{"confidence=100", "local_evidence=true", "reason=confidence_100"} {
		if !strings.Contains(out, want) {
			t.Errorf("expected ban-decision log to contain %q, got: %s", want, out)
		}
	}
}

func TestConfidence100_BelowThresholdNoban(t *testing.T) {
	const ip = "5.6.7.8"
	for _, score := range []int{0, 50, 99} {
		ev := newEval(t, true, &fakeEnricher{abuseScore: score})
		withLocalEvent(t, ev, ip)
		d := ev.EvaluateConfidence(context.Background(), ip)
		if d.ShouldBan {
			t.Errorf("score=%d: expected no ban, got ShouldBan=true", score)
		}
		if d.SkipReason != "confidence_below_100" {
			t.Errorf("score=%d: expected skip reason confidence_below_100, got %q", score, d.SkipReason)
		}
	}
}

func TestConfidence100_ProtectedIPPreventsban(t *testing.T) {
	// RFC1918 — guardIP fires before local-evidence check; AbuseIPDB must not be called.
	fe := &fakeEnricher{abuseScore: 100}
	ev := newEval(t, true, fe)
	d := ev.EvaluateConfidence(context.Background(), "192.168.1.1")
	if d.ShouldBan {
		t.Fatalf("expected skip for RFC1918, got ShouldBan=true")
	}
	if d.SkipReason != "not_public_ip" && d.SkipReason != "protected_target" {
		t.Errorf("unexpected skip reason %q", d.SkipReason)
	}
	if fe.callCount != 0 {
		t.Errorf("expected AbuseIPDB Enrich not called for protected IP, got callCount=%d", fe.callCount)
	}
}

func TestConfidence100_LoopbackPreventsban(t *testing.T) {
	fe := &fakeEnricher{abuseScore: 100}
	ev := newEval(t, true, fe)
	d := ev.EvaluateConfidence(context.Background(), "127.0.0.1")
	if d.ShouldBan {
		t.Fatal("expected skip for loopback")
	}
	if fe.callCount != 0 {
		t.Errorf("expected AbuseIPDB Enrich not called for loopback, got callCount=%d", fe.callCount)
	}
}

func TestConfidence100_CloudflareIPPreventsban(t *testing.T) {
	// 173.245.48.1 is in the Cloudflare range 173.245.48.0/20
	fe := &fakeEnricher{abuseScore: 100}
	ev := newEval(t, true, fe)
	d := ev.EvaluateConfidence(context.Background(), "173.245.48.1")
	if d.ShouldBan {
		t.Fatal("expected skip for Cloudflare IP")
	}
	if fe.callCount != 0 {
		t.Errorf("expected AbuseIPDB Enrich not called for Cloudflare IP, got callCount=%d", fe.callCount)
	}
}

func TestConfidence100_EnrichmentErrorFailOpen(t *testing.T) {
	const ip = "5.6.7.8"
	ev := newEval(t, true, &fakeEnricher{err: context.DeadlineExceeded})
	withLocalEvent(t, ev, ip)
	d := ev.EvaluateConfidence(context.Background(), ip)
	if d.ShouldBan {
		t.Fatal("expected fail-open (no ban) on enrichment error")
	}
	if d.SkipReason == "" {
		t.Error("expected non-empty SkipReason on error")
	}
}

func TestConfidence100_DuplicateBanPrevented(t *testing.T) {
	const ip = "5.6.7.8"
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	withLocalEvent(t, ev, ip)
	// First evaluation — should ban
	d := ev.EvaluateConfidence(context.Background(), ip)
	if !d.ShouldBan {
		t.Fatal("expected first ban to succeed")
	}
	ev.RecordBan(ip)
	// Second evaluation — deduped at guardIP before reaching local-evidence check
	d2 := ev.EvaluateConfidence(context.Background(), ip)
	if d2.ShouldBan {
		t.Error("expected duplicate ban to be skipped")
	}
	if d2.SkipReason != "already_banned" {
		t.Errorf("expected already_banned skip, got %q", d2.SkipReason)
	}
}

// --- burst rule tests ---

func TestBurst31_TriggersBan(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	now := time.Now()
	for i := 0; i < 31; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: now})
	}
	d := ev.EvaluateBurst(ip)
	if !d.ShouldBan {
		t.Fatalf("expected burst ban at 31 events, got SkipReason=%q", d.SkipReason)
	}
	if d.Reason != "burst_malicious" {
		t.Errorf("expected reason burst_malicious, got %q", d.Reason)
	}
}

func TestBurst30_DoesNotTriggerBan(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	now := time.Now()
	for i := 0; i < 30; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: now})
	}
	d := ev.EvaluateBurst(ip)
	if d.ShouldBan {
		t.Error("expected 30 events (threshold) to NOT trigger ban (must be >30)")
	}
}

func TestBurstBenignEvents_DoNotCount(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	now := time.Now()
	// 40 benign events — should not trigger ban
	for i := 0; i < 40; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "benign_probe", Timestamp: now})
	}
	d := ev.EvaluateBurst(ip)
	if d.ShouldBan {
		t.Error("expected benign events to not trigger burst ban")
	}
}

func TestBurstSpreadEvents_DoNotTriggerBan(t *testing.T) {
	// 40 events spread over 2 minutes (one every 3s) — max ~10 in any 30s window,
	// well below the threshold of 30.
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	base := time.Now().Add(-2 * time.Minute)
	for i := 0; i < 40; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{
			IP:        ip,
			AbuseType: "scanner",
			Timestamp: base.Add(time.Duration(i) * 3 * time.Second),
			RayID:     fmt.Sprintf("ray-%03d", i),
		})
	}
	d := ev.EvaluateBurst(ip)
	if d.ShouldBan {
		t.Error("expected events spread over 2min to not trigger burst ban (max ~10/30s)")
	}
}

func TestBurstStaleEvents_DoNotCount(t *testing.T) {
	// Events older than burstPruneLookback (15min) are dropped; burst not triggered.
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	stale := time.Now().Add(-20 * time.Minute)
	for i := 0; i < 40; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: stale})
	}
	d := ev.EvaluateBurst(ip)
	if d.ShouldBan {
		t.Error("expected events older than 15min to not trigger burst ban")
	}
}

func TestBurstRayIDDedup_SameEventNotCounted(t *testing.T) {
	// 40 submissions of the same ray_id — only 1 should be counted (no ban).
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	now := time.Now()
	for i := 0; i < 40; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{
			IP:        ip,
			AbuseType: "scanner",
			Timestamp: now,
			RayID:     "ray-dedupe",
		})
	}
	d := ev.EvaluateBurst(ip)
	if d.ShouldBan {
		t.Error("expected same ray_id repeated 40 times to count only once, not triggering burst ban")
	}
}

func TestBurstShadowMode_NeverMutates(t *testing.T) {
	ev := newEval(t, false, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	now := time.Now()
	for i := 0; i < 31; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: now})
	}
	d := ev.EvaluateBurst(ip)
	if !d.ShouldBan {
		t.Fatalf("expected burst ban decision, got SkipReason=%q", d.SkipReason)
	}
	if !d.Shadow {
		t.Error("expected Shadow=true in shadow mode")
	}
}

func TestBurstProtectedIPPreventsban(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	// Allowlisted CF IP
	const cfIP = "173.245.48.2"
	now := time.Now()
	for i := 0; i < 40; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: cfIP, AbuseType: "scanner", Timestamp: now})
	}
	d := ev.EvaluateBurst(cfIP)
	if d.ShouldBan {
		t.Error("expected CF IP to be exempt from burst ban")
	}
}

func TestBurstDedup_SecondBanSkipped(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	now := time.Now()
	for i := 0; i < 31; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: now})
	}
	d1 := ev.EvaluateBurst(ip)
	if !d1.ShouldBan {
		t.Fatal("first evaluation should trigger ban")
	}
	ev.RecordBan(ip)
	d2 := ev.EvaluateBurst(ip)
	if d2.ShouldBan {
		t.Error("second evaluation should be deduped")
	}
}

// --- HasLocalEvidence tests (direct BurstCounter coverage) ---

func TestHasLocalEvidence_StaleEventIgnored(t *testing.T) {
	// Events older than burstPruneLookback (15min) must not satisfy the local-evidence gate.
	bc := autoban.NewBurstCounter()
	stale := time.Now().Add(-20 * time.Minute)
	bc.Record("1.2.3.4", "", stale)
	if bc.HasLocalEvidence("1.2.3.4", time.Now()) {
		t.Error("expected stale event (>15min old) to be ignored by HasLocalEvidence")
	}
}

func TestHasLocalEvidence_RayIDDedupStillCounts(t *testing.T) {
	// 40 submissions of the same ray_id must result in exactly 1 stored event,
	// which is sufficient for HasLocalEvidence to return true.
	bc := autoban.NewBurstCounter()
	now := time.Now()
	for i := 0; i < 40; i++ {
		bc.Record("1.2.3.4", "ray-dedup", now)
	}
	if !bc.HasLocalEvidence("1.2.3.4", time.Now()) {
		t.Error("expected HasLocalEvidence=true: deduped recording still counts as 1 event")
	}
}

// --- Quota guard test — uses DefaultRegistry (global); do not run in parallel. ---

func TestConfidence100_QuotaExhausted_NoAbuseIPDBCall(t *testing.T) {
	// When AbuseIPDB quota is EXHAUSTED, EvaluateConfidence must skip the Enrich
	// call and return abuseipdb_quota_constrained.
	t.Cleanup(quota.ResetDefaultRegistry)
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:         "abuseipdb",
		PercentKnown:     true,
		RemainingPercent: 0, // → Exhausted
	})

	const ip = "5.6.7.8"
	fe := &fakeEnricher{abuseScore: 100}
	ev := newEval(t, true, fe)
	withLocalEvent(t, ev, ip)
	d := ev.EvaluateConfidence(context.Background(), ip)
	if d.ShouldBan {
		t.Fatal("expected no ban when quota is exhausted")
	}
	if d.SkipReason != "abuseipdb_quota_constrained" {
		t.Errorf("expected skip reason abuseipdb_quota_constrained, got %q", d.SkipReason)
	}
	if fe.callCount != 0 {
		t.Errorf("expected AbuseIPDB Enrich not called when quota exhausted, got callCount=%d", fe.callCount)
	}
}

func TestConfidence100_QuotaThrottled_NoAbuseIPDBCall(t *testing.T) {
	t.Cleanup(quota.ResetDefaultRegistry)
	quota.DefaultRegistry().Record(quota.Observation{
		Provider:         "abuseipdb",
		PercentKnown:     true,
		RemainingPercent: 3, // ≤5% → Throttled
	})

	const ip = "5.6.7.8"
	fe := &fakeEnricher{abuseScore: 100}
	ev := newEval(t, true, fe)
	withLocalEvent(t, ev, ip)
	d := ev.EvaluateConfidence(context.Background(), ip)
	if d.ShouldBan {
		t.Fatal("expected no ban when quota is throttled")
	}
	if d.SkipReason != "abuseipdb_quota_constrained" {
		t.Errorf("expected skip reason abuseipdb_quota_constrained, got %q", d.SkipReason)
	}
	if fe.callCount != 0 {
		t.Errorf("expected AbuseIPDB Enrich not called when quota throttled, got callCount=%d", fe.callCount)
	}
}

// --- EvaluateExternalBurst tests (used by nginxerrors HTTP-error escalation) ---

func TestEvaluateExternalBurst_LiveModeTriggersBan(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{})
	d := ev.EvaluateExternalBurst("9.9.9.9", "http_error_burst")
	if !d.ShouldBan {
		t.Fatalf("expected ban decision, got SkipReason=%q", d.SkipReason)
	}
	if d.Reason != "http_error_burst" {
		t.Errorf("expected reason to pass through, got %q", d.Reason)
	}
	if d.Shadow {
		t.Error("expected Shadow=false in live mode")
	}
}

func TestEvaluateExternalBurst_ShadowModeNeverBans(t *testing.T) {
	ev := newEval(t, false, &fakeEnricher{})
	d := ev.EvaluateExternalBurst("9.9.9.9", "http_error_burst")
	if !d.ShouldBan {
		t.Fatalf("expected ShouldBan=true with Shadow=true, got SkipReason=%q", d.SkipReason)
	}
	if !d.Shadow {
		t.Error("expected Shadow=true in shadow mode; callers must never mutate on a shadow decision")
	}
}

func TestEvaluateExternalBurst_ProtectedIPNeverBans(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{})
	const cfIP = "173.245.48.2" // allowlisted Cloudflare IP
	d := ev.EvaluateExternalBurst(cfIP, "http_error_burst")
	if d.ShouldBan {
		t.Error("expected protected/allowlisted IP to be exempt from external burst ban")
	}
	if d.SkipReason != "protected_target" {
		t.Errorf("expected skip reason protected_target, got %q", d.SkipReason)
	}
}

func TestEvaluateExternalBurst_PrivateIPNeverBans(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{})
	d := ev.EvaluateExternalBurst("10.0.0.5", "http_error_burst")
	if d.ShouldBan {
		t.Error("expected RFC1918 IP to be exempt from external burst ban")
	}
	if d.SkipReason != "not_public_ip" {
		t.Errorf("expected skip reason not_public_ip, got %q", d.SkipReason)
	}
}

func TestEvaluateExternalBurst_DedupSkipsSecondBan(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{})
	const ip = "9.9.9.9"
	d1 := ev.EvaluateExternalBurst(ip, "http_error_burst")
	if !d1.ShouldBan {
		t.Fatal("first evaluation should authorize ban")
	}
	ev.RecordBan(ip)
	d2 := ev.EvaluateExternalBurst(ip, "http_error_burst")
	if d2.ShouldBan {
		t.Error("second evaluation should be deduped")
	}
}
