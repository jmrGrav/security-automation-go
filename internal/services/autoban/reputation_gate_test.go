package autoban_test

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/services/autoban"
)

// fakeReputationGate lets tests dictate exactly what decision the evaluator
// sees without exercising the real cross-provider gate logic.
type fakeReputationGate struct {
	decision reputation.Decision
	calls    int
}

func (f *fakeReputationGate) EvaluateBan(_ context.Context, _ string, _ reputation.LocalSignal) reputation.Decision {
	f.calls++
	return f.decision
}

// --- EvaluateConfidence + reputation gate ---

func TestEvaluateConfidence_ReputationGate_EnforceMode_BlocksBan(t *testing.T) {
	const ip = "5.6.7.8"
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	withLocalEvent(t, ev, ip)

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:   reputation.ActionSuppressLowConfidence,
		Reason:   reputation.ReasonSuppressedLowReputationConfidence,
		AllowBan: false,
		Shadow:   false,
	}}
	ev.SetReputationGate(gate)

	d := ev.EvaluateConfidence(context.Background(), ip)
	if d.ShouldBan {
		t.Fatalf("expected reputation gate to block ban, got %+v", d)
	}
	if d.SkipReason != "reputation_gate:"+reputation.ReasonSuppressedLowReputationConfidence {
		t.Fatalf("unexpected skip reason: %q", d.SkipReason)
	}
	if gate.calls != 1 {
		t.Fatalf("expected gate consulted exactly once, got %d", gate.calls)
	}
}

func TestEvaluateConfidence_ReputationGate_ShadowMode_BanStillProceeds(t *testing.T) {
	const ip = "5.6.7.8"
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	withLocalEvent(t, ev, ip)

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:   reputation.ActionSuppressLowConfidence,
		Reason:   reputation.ReasonSuppressedLowReputationConfidence,
		AllowBan: false,
		Shadow:   true, // gate itself in shadow mode: decision logged only
	}}
	ev.SetReputationGate(gate)

	d := ev.EvaluateConfidence(context.Background(), ip)
	if !d.ShouldBan {
		t.Fatalf("expected pre-existing ban decision to proceed under shadow gate, got %+v", d)
	}
	if gate.calls != 1 {
		t.Fatalf("expected gate consulted exactly once, got %d", gate.calls)
	}
}

func TestEvaluateConfidence_ReputationGate_Allows_BanProceeds(t *testing.T) {
	const ip = "5.6.7.8"
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	withLocalEvent(t, ev, ip)

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:   reputation.ActionAllow,
		Reason:   reputation.ReasonAllowedCorroborated,
		AllowBan: true,
		Shadow:   false,
	}}
	ev.SetReputationGate(gate)

	d := ev.EvaluateConfidence(context.Background(), ip)
	if !d.ShouldBan {
		t.Fatalf("expected ban to proceed when gate allows, got %+v", d)
	}
}

func TestEvaluateConfidence_NilGate_NoBehaviorChange(t *testing.T) {
	const ip = "5.6.7.8"
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	withLocalEvent(t, ev, ip)
	// No SetReputationGate call — must behave exactly as before this feature.
	d := ev.EvaluateConfidence(context.Background(), ip)
	if !d.ShouldBan || d.Reason != "confidence_100" {
		t.Fatalf("expected unchanged confidence_100 ban decision, got %+v", d)
	}
}

func TestEvaluateConfidence_ReputationGate_NeverConsultedWhenPriorGuardsFail(t *testing.T) {
	// No local evidence recorded: the existing no_local_evidence guard must
	// short-circuit before the reputation gate is ever consulted, proving the
	// gate is a strictly additional restriction layered on top.
	const ip = "5.6.7.8"
	ev := newEval(t, true, &fakeEnricher{abuseScore: 100})
	gate := &fakeReputationGate{decision: reputation.Decision{AllowBan: true}}
	ev.SetReputationGate(gate)

	d := ev.EvaluateConfidence(context.Background(), ip)
	if d.ShouldBan {
		t.Fatalf("expected no_local_evidence guard to block ban regardless of gate, got %+v", d)
	}
	if d.SkipReason != "no_local_evidence" {
		t.Fatalf("unexpected skip reason: %q", d.SkipReason)
	}
	if gate.calls != 0 {
		t.Fatalf("expected gate never consulted when a prior guard already blocked, got %d calls", gate.calls)
	}
}

// --- EvaluateBurst + reputation gate ---

func TestEvaluateBurst_ReputationGate_EnforceMode_BlocksBan(t *testing.T) {
	const ip = "9.9.9.9"
	ev := newEval(t, true, &fakeEnricher{})
	now := time.Now()
	for i := 0; i < autoban.BurstThreshold+1; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: now, RayID: ""})
	}

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:   reputation.ActionSuppressLowConfidence,
		Reason:   reputation.ReasonSuppressedLowReputationConfidence,
		AllowBan: false,
		Shadow:   false,
	}}
	ev.SetReputationGate(gate)

	d := ev.EvaluateBurst(ip)
	if d.ShouldBan {
		t.Fatalf("expected reputation gate to block burst ban, got %+v", d)
	}
	if d.SkipReason != "reputation_gate:"+reputation.ReasonSuppressedLowReputationConfidence {
		t.Fatalf("unexpected skip reason: %q", d.SkipReason)
	}
}

func TestEvaluateBurst_ReputationGate_ShadowMode_BanStillProceeds(t *testing.T) {
	const ip = "9.9.9.10"
	ev := newEval(t, true, &fakeEnricher{})
	now := time.Now()
	for i := 0; i < autoban.BurstThreshold+1; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: now, RayID: ""})
	}

	gate := &fakeReputationGate{decision: reputation.Decision{
		Action:   reputation.ActionSuppressLowConfidence,
		Reason:   reputation.ReasonSuppressedLowReputationConfidence,
		AllowBan: false,
		Shadow:   true,
	}}
	ev.SetReputationGate(gate)

	d := ev.EvaluateBurst(ip)
	if !d.ShouldBan {
		t.Fatalf("expected pre-existing burst ban decision to proceed under shadow gate, got %+v", d)
	}
}

func TestEvaluateBurst_NilGate_NoBehaviorChange(t *testing.T) {
	const ip = "9.9.9.11"
	ev := newEval(t, true, &fakeEnricher{})
	now := time.Now()
	for i := 0; i < autoban.BurstThreshold+1; i++ {
		ev.RecordMalicious(autoban.MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: now, RayID: ""})
	}
	d := ev.EvaluateBurst(ip)
	if !d.ShouldBan || d.Reason != "burst_malicious" {
		t.Fatalf("expected unchanged burst_malicious ban decision, got %+v", d)
	}
}
