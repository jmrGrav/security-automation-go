package reputation

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/security/quota"
)

func TestEvaluate_AbuseIPDBZero_WeakLocal_Suppresses(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		AbuseIPDB: ProviderSignal{Available: true, Score: 0},
		Local:     LocalSignal{Strength: SignalWeak},
	}
	d := Evaluate(policy, signals, false)
	if d.Action != ActionSuppressLowConfidence {
		t.Fatalf("expected suppress, got %v", d.Action)
	}
	if d.Reason != ReasonSuppressedLowReputationConfidence {
		t.Fatalf("unexpected reason %q", d.Reason)
	}
	if d.AllowReport || d.AllowBan {
		t.Fatalf("expected no allow, got %+v", d)
	}
}

func TestEvaluate_AbuseIPDBZero_ConfirmedHostileLocal_InvestigationShadow(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		AbuseIPDB: ProviderSignal{Available: true, Score: 0},
		Local:     LocalSignal{Strength: SignalConfirmedHostile, AbuseType: "exploit_attempt"},
	}
	d := Evaluate(policy, signals, false)
	if d.Action != ActionInvestigationShadow {
		t.Fatalf("expected investigation_shadow, got %v", d.Action)
	}
	if d.Reason != ReasonInvestigationShadow {
		t.Fatalf("unexpected reason %q", d.Reason)
	}
	if d.AllowReport {
		t.Fatalf("must not auto-report on investigation_shadow")
	}
}

func TestEvaluate_HighConfidence_WithLocalEvidence_Allows(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		AbuseIPDB: ProviderSignal{Available: true, Score: 90},
		Local:     LocalSignal{Strength: SignalConfirmedHostile},
	}
	d := Evaluate(policy, signals, false)
	if d.Action != ActionAllow || !d.AllowReport {
		t.Fatalf("expected allow, got %+v", d)
	}
}

func TestEvaluate_HighConfidence_NoLocalEvidence_NeverAllowsAlone(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		AbuseIPDB: ProviderSignal{Available: true, Score: 100},
		Local:     LocalSignal{Strength: SignalNone},
	}
	d := Evaluate(policy, signals, true)
	if d.AllowBan {
		t.Fatalf("AbuseIPDB must never be sole authority for an allow, got %+v", d)
	}
}

func TestEvaluate_VirusTotalClean_AbuseIPDBLow_Suppresses(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		AbuseIPDB:  ProviderSignal{Available: true, Score: 5},
		VirusTotal: ProviderSignal{Available: true, Score: 0},
		Local:      LocalSignal{Strength: SignalWeak},
	}
	d := Evaluate(policy, signals, false)
	if d.Action != ActionSuppressLowConfidence {
		t.Fatalf("expected suppress, got %v", d.Action)
	}
}

func TestEvaluate_VirusTotalMalicious_WithLocalEvidence_Allows(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		AbuseIPDB:  ProviderSignal{Available: true, Score: 0},
		VirusTotal: ProviderSignal{Available: true, Score: 5}, // malicious engine count > 0
		Local:      LocalSignal{Strength: SignalConfirmedHostile},
	}
	d := Evaluate(policy, signals, false)
	if d.Action != ActionAllow || !d.AllowReport {
		t.Fatalf("expected allow on VT malicious + local evidence, got %+v", d)
	}
}

func TestEvaluate_VirusTotalMalicious_NoLocalEvidence_NeverAllowsAlone(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		VirusTotal: ProviderSignal{Available: true, Score: 10},
		Local:      LocalSignal{Strength: SignalNone},
	}
	d := Evaluate(policy, signals, false)
	if d.AllowReport {
		t.Fatalf("VirusTotal alone must never force an allow, got %+v", d)
	}
}

func TestEvaluate_ProviderUnavailable_FailsOpenToEvidenceOnly(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		AbuseIPDB:  ProviderSignal{Available: false, Err: errors.New("boom")},
		VirusTotal: ProviderSignal{Available: false, Err: errors.New("boom")},
		Local:      LocalSignal{Strength: SignalWeak},
	}
	d := Evaluate(policy, signals, false)
	if !d.ProviderUnavailable {
		t.Fatalf("expected ProviderUnavailable=true, got %+v", d)
	}
	if d.Reason != ReasonProviderUnavailable {
		t.Fatalf("expected provider_unavailable reason, got %q", d.Reason)
	}
	if d.AllowReport {
		t.Fatalf("weak local signal + both providers down must not allow, got %+v", d)
	}
}

func TestEvaluate_ProviderUnavailable_ConfirmedHostileLocal_StillEscalates(t *testing.T) {
	policy := DefaultPolicy()
	signals := Signals{
		AbuseIPDB:  ProviderSignal{Available: false},
		VirusTotal: ProviderSignal{Available: false},
		Local:      LocalSignal{Strength: SignalConfirmedHostile},
	}
	d := Evaluate(policy, signals, true)
	if !d.AllowBan {
		t.Fatalf("confirmed hostile local evidence should still allow when both providers are down, got %+v", d)
	}
	if !d.ProviderUnavailable {
		t.Fatalf("expected ProviderUnavailable=true")
	}
}

func TestEvaluate_ShadowMode_DecisionComputedButMarkedShadow(t *testing.T) {
	policy := DefaultPolicy()
	policy.Mode = ModeShadow
	signals := Signals{
		AbuseIPDB: ProviderSignal{Available: true, Score: 90},
		Local:     LocalSignal{Strength: SignalConfirmedHostile},
	}
	d := Evaluate(policy, signals, true)
	if !d.Shadow {
		t.Fatalf("expected Shadow=true under ModeShadow")
	}
	// Evaluate itself never mutates anything regardless of mode — Shadow is
	// purely informational for the caller to act on.
	if !d.AllowBan {
		t.Fatalf("decision content itself should be unaffected by mode")
	}
}

func TestEvaluate_EnforceMode_NotShadow(t *testing.T) {
	policy := DefaultPolicy()
	policy.Mode = ModeEnforce
	signals := Signals{
		AbuseIPDB: ProviderSignal{Available: true, Score: 90},
		Local:     LocalSignal{Strength: SignalConfirmedHostile},
	}
	d := Evaluate(policy, signals, true)
	if d.Shadow {
		t.Fatalf("expected Shadow=false under ModeEnforce")
	}
}

// fakeEnricher lets FetchSignals tests control what the enrichment service
// returns without standing up a real HTTP client.
type fakeEnricher struct {
	summary enrichment.EnrichmentSummary
	err     error
	calls   []enrichment.LookupOptions
}

func (f *fakeEnricher) Enrich(_ context.Context, _ netip.Addr, opts enrichment.LookupOptions) (enrichment.EnrichmentSummary, error) {
	f.calls = append(f.calls, opts)
	return f.summary, f.err
}

type fakeQuota struct {
	state quota.State
	ok    bool
}

func (f fakeQuota) State(string) (quota.State, bool) { return f.state, f.ok }

func TestFetchSignals_UsesReputationCheckFlagNotManualForensics(t *testing.T) {
	enricher := &fakeEnricher{summary: enrichment.EnrichmentSummary{
		Providers: []enrichment.ProviderVerdict{
			{Provider: "abuseipdb", Score: 42},
			{Provider: "virustotal", Score: 3},
		},
	}}
	policy := DefaultPolicy()
	signals := FetchSignals(context.Background(), enricher, nil, "1.2.3.4", policy, LocalSignal{Strength: SignalWeak})
	if !signals.AbuseIPDB.Available || signals.AbuseIPDB.Score != 42 {
		t.Fatalf("expected abuseipdb signal 42, got %+v", signals.AbuseIPDB)
	}
	if !signals.VirusTotal.Available || signals.VirusTotal.Score != 3 {
		t.Fatalf("expected virustotal signal 3, got %+v", signals.VirusTotal)
	}
	if len(enricher.calls) != 1 || !enricher.calls[0].ReputationCheck || enricher.calls[0].ManualForensics {
		t.Fatalf("expected a single ReputationCheck=true, ManualForensics=false call, got %+v", enricher.calls)
	}
}

func TestFetchSignals_QuotaExhausted_SkipsAbuseIPDBCheckButTriesVirusTotal(t *testing.T) {
	enricher := &fakeEnricher{summary: enrichment.EnrichmentSummary{
		Providers: []enrichment.ProviderVerdict{
			{Provider: "virustotal", Score: 0},
		},
	}}
	q := fakeQuota{state: quota.Exhausted, ok: true}
	policy := DefaultPolicy()
	signals := FetchSignals(context.Background(), enricher, q, "1.2.3.4", policy, LocalSignal{Strength: SignalWeak})
	if signals.AbuseIPDB.Available {
		t.Fatalf("expected AbuseIPDB unavailable due to quota, got %+v", signals.AbuseIPDB)
	}
	if signals.AbuseIPDB.Note != "abuseipdb_quota_constrained" {
		t.Fatalf("expected quota note, got %q", signals.AbuseIPDB.Note)
	}
	if !signals.VirusTotal.Available {
		t.Fatalf("expected VirusTotal still attempted despite AbuseIPDB quota constraint")
	}
}

func TestFetchSignals_EnrichError_FailsOpenNoCrash(t *testing.T) {
	enricher := &fakeEnricher{err: errors.New("network down")}
	policy := DefaultPolicy()
	signals := FetchSignals(context.Background(), enricher, nil, "1.2.3.4", policy, LocalSignal{Strength: SignalWeak})
	if signals.AbuseIPDB.Available {
		t.Fatalf("expected unavailable on error, got %+v", signals.AbuseIPDB)
	}
	d := Evaluate(policy, signals, false)
	if d.AllowReport {
		t.Fatalf("error + weak local signal must not allow, got %+v", d)
	}
	if !d.ProviderUnavailable {
		t.Fatalf("expected ProviderUnavailable=true")
	}
}

func TestGate_EvaluateReportAndBan(t *testing.T) {
	enricher := &fakeEnricher{summary: enrichment.EnrichmentSummary{
		Providers: []enrichment.ProviderVerdict{{Provider: "abuseipdb", Score: 80}},
	}}
	g := NewGate(enricher, nil, DefaultPolicy())
	d := g.EvaluateReport(context.Background(), "5.6.7.8", LocalSignal{Strength: SignalConfirmedHostile})
	if !d.AllowReport {
		t.Fatalf("expected allow report, got %+v", d)
	}
	d2 := g.EvaluateBan(context.Background(), "5.6.7.8", LocalSignal{Strength: SignalConfirmedHostile})
	if !d2.AllowBan {
		t.Fatalf("expected allow ban, got %+v", d2)
	}
}
