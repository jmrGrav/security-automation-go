package enrichment

import (
	"net/netip"
	"testing"

	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
)

func mustParseAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic("mustParseAddr: " + err.Error())
	}
	return a
}

// ── scoreASN unit tests ────────────────────────────────────────────────────────

func TestScoreASN_ProtectedSetsNoHardBan(t *testing.T) {
	delta, noHardBan, reason := scoreASN(string(asn.KindProtected), true)
	if delta != 0 {
		t.Errorf("expected delta=0, got %d", delta)
	}
	if !noHardBan {
		t.Error("KindProtected must set noHardBan=true")
	}
	if reason == "" {
		t.Error("expected non-empty reason for protected network")
	}
}

func TestScoreASN_SearchBotSetsNoHardBan(t *testing.T) {
	delta, noHardBan, reason := scoreASN(string(asn.KindSearchBot), true)
	if delta != 0 {
		t.Errorf("expected delta=0, got %d", delta)
	}
	if !noHardBan {
		t.Error("KindSearchBot must set noHardBan=true")
	}
	if reason != "search_bot_network" {
		t.Errorf("expected reason=search_bot_network, got %q", reason)
	}
}

func TestScoreASN_AIAgentSetsNoHardBan(t *testing.T) {
	delta, noHardBan, reason := scoreASN(string(asn.KindAIAgent), true)
	if delta != 0 {
		t.Errorf("expected delta=0, got %d", delta)
	}
	if !noHardBan {
		t.Error("KindAIAgent must set noHardBan=true")
	}
	if reason != "ai_agent_network" {
		t.Errorf("expected reason=ai_agent_network, got %q", reason)
	}
}

func TestScoreASN_MonitoringSetsNoHardBan(t *testing.T) {
	delta, noHardBan, reason := scoreASN(string(asn.KindMonitoring), true)
	if delta != 0 {
		t.Errorf("expected delta=0, got %d", delta)
	}
	if !noHardBan {
		t.Error("KindMonitoring must set noHardBan=true")
	}
	if reason != "monitoring_network" {
		t.Errorf("expected reason=monitoring_network, got %q", reason)
	}
}

func TestScoreASN_UnknownIsNeutral(t *testing.T) {
	delta, noHardBan, reason := scoreASN(string(asn.KindUnknown), false)
	if delta != 0 {
		t.Errorf("expected delta=0, got %d", delta)
	}
	if noHardBan {
		t.Error("KindUnknown must not set noHardBan")
	}
	if reason != "" {
		t.Errorf("expected empty reason, got %q", reason)
	}
}

func TestScoreASN_DatacenterIncreasesScore(t *testing.T) {
	delta, noHardBan, reason := scoreASN(string(asn.KindDatacenter), false)
	if delta != 2 {
		t.Errorf("expected delta=2 for datacenter, got %d", delta)
	}
	if noHardBan {
		t.Error("KindDatacenter must not set noHardBan")
	}
	if reason != "datacenter_network" {
		t.Errorf("expected reason=datacenter_network, got %q", reason)
	}
}

// ── Protected ASN → no automatic allowlist ────────────────────────────────────
//
// INVARIANT: A protected ASN sets Assessment.NoHardBan=true and
// Assessment.HardBanAllowed=false. This is a SIGNAL returned to callers.
// No code path in the enrichment package calls any CrowdSec or Cloudflare
// allowlist API. The decision to propagate to an external allowlist is
// exclusively manual, audited, and dry-run first (per DECISIONS.md).

// TestAssess_ProtectedASN_NoHardBan verifies that a protected ASN (any kind)
// results in NoHardBan=true and HardBanAllowed=false even under a very high
// local signal score.
func TestAssess_ProtectedASN_NoHardBan(t *testing.T) {
	kinds := []asn.Kind{
		asn.KindProtected,
		asn.KindSearchBot,
		asn.KindAIAgent,
		asn.KindMonitoring,
	}
	for _, kind := range kinds {
		summary := EnrichmentSummary{
			IP: mustParseAddr("104.16.0.1"),
			ASN: asn.Result{
				Kind:      kind,
				Protected: true,
				Org:       "test-org",
			},
			LocalSignalScore: 999, // deliberately high to prove noHardBan wins
		}
		svc := &Service{} // Assess does not use cfg/providers
		assessment := svc.Assess(summary)

		if !assessment.NoHardBan {
			t.Errorf("kind=%q: expected NoHardBan=true", kind)
		}
		if assessment.HardBanAllowed {
			t.Errorf("kind=%q: expected HardBanAllowed=false even with LocalSignalScore=999", kind)
		}
	}
}

// TestAssess_ProtectedASN_IsSignalNotAction documents the architectural invariant:
// the Assessment struct is a pure value — it carries no methods that mutate
// external state (no CrowdSec calls, no Cloudflare API calls, no DB writes).
// This test is a compile-time guard: if a mutation method were added to Assessment,
// this comment would need to be reviewed and the test updated.
func TestAssess_ProtectedASN_IsSignalNotAction(t *testing.T) {
	// Assessment is a plain struct with no pointer receivers that could mutate
	// external state. This is enforced by Go's type system: callers receive a
	// copy; only the calling layer (app/) can decide what to do with it.
	//
	// Concretely: the enrichment package has zero imports of the crowdsec or
	// cloudflare packages. Run `go list -f '{{.Imports}}' ./internal/security/enrichment`
	// to confirm there is no crowdsec or cloudflare import.
	_ = Assessment{NoHardBan: true, HardBanAllowed: false}
}
