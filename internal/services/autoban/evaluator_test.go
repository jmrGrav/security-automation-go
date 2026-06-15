package autoban_test

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/autoban"
)

// --- fake enricher ---

type fakeEnricher struct {
	abuseScore int
	err        error
}

func (f *fakeEnricher) Enrich(_ context.Context, _ netip.Addr, _ enrichment.LookupOptions) (enrichment.EnrichmentSummary, error) {
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

// --- confidence-100 tests ---

func TestConfidence100_TriggersBanInLiveMode(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	d := ev.EvaluateConfidence(context.Background(), "5.6.7.8")
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
	ev := newEval(t, false, &fakeEnricher{abuseScore: 100})
	d := ev.EvaluateConfidence(context.Background(), "5.6.7.8")
	if !d.ShouldBan {
		t.Fatalf("expected ban decision, got SkipReason=%q", d.SkipReason)
	}
	if !d.Shadow {
		t.Error("expected Shadow=true in shadow mode")
	}
}

func TestConfidence100_BelowThresholdNoban(t *testing.T) {
	for _, score := range []int{0, 50, 99} {
		ev := newEval(t, true, &fakeEnricher{abuseScore: score})
		d := ev.EvaluateConfidence(context.Background(), "5.6.7.8")
		if d.ShouldBan {
			t.Errorf("score=%d: expected no ban, got ShouldBan=true", score)
		}
	}
}

func TestConfidence100_ProtectedIPPreventsban(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	// RFC1918 — trust registry covers this
	d := ev.EvaluateConfidence(context.Background(), "192.168.1.1")
	if d.ShouldBan {
		t.Fatalf("expected skip for RFC1918, got ShouldBan=true")
	}
	if d.SkipReason != "not_public_ip" && d.SkipReason != "protected_target" {
		t.Errorf("unexpected skip reason %q", d.SkipReason)
	}
}

func TestConfidence100_LoopbackPreventsban(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	d := ev.EvaluateConfidence(context.Background(), "127.0.0.1")
	if d.ShouldBan {
		t.Fatal("expected skip for loopback")
	}
}

func TestConfidence100_CloudflareIPPreventsban(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	// 173.245.48.1 is in the Cloudflare range 173.245.48.0/20
	d := ev.EvaluateConfidence(context.Background(), "173.245.48.1")
	if d.ShouldBan {
		t.Fatal("expected skip for Cloudflare IP")
	}
}

func TestConfidence100_EnrichmentErrorFailOpen(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{err: context.DeadlineExceeded})
	d := ev.EvaluateConfidence(context.Background(), "5.6.7.8")
	if d.ShouldBan {
		t.Fatal("expected fail-open (no ban) on enrichment error")
	}
	if d.SkipReason == "" {
		t.Error("expected non-empty SkipReason on error")
	}
}

func TestConfidence100_DuplicateBanPrevented(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	const ip = "5.6.7.8"
	// First evaluation — should ban
	d := ev.EvaluateConfidence(context.Background(), ip)
	if !d.ShouldBan {
		t.Fatal("expected first ban to succeed")
	}
	ev.RecordBan(ip)
	// Second evaluation — should be deduped
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

func TestBurstExpiredEvents_DoNotCount(t *testing.T) {
	ev := newEval(t, true, &fakeEnricher{abuseScore: 0})
	const ip = "1.2.3.4"
	old := time.Now().Add(-60 * time.Second) // older than 30s burst window
	for i := 0; i < 40; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: old})
	}
	d := ev.EvaluateBurst(ip)
	if d.ShouldBan {
		t.Error("expected expired events to not trigger burst ban")
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
