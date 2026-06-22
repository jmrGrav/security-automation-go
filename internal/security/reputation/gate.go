// Package reputation implements a cross-provider reputation gate that sits
// in front of AbuseIPDB report submission and Cloudflare ban execution.
//
// # Why this package exists
//
// AbuseIPDB Check (and VirusTotal) are write-once external signals: the rest
// of the pipeline previously only ever *wrote* to AbuseIPDB (submitting
// reports) without ever reading its own Check verdict back before deciding
// whether a report or a ban was warranted. That produced cases where an IP
// was reported to AbuseIPDB while AbuseIPDB itself showed a 0% confidence
// score for that IP — a one-directional, write-only relationship.
//
// This package closes that loop: before a report is submitted or a ban is
// executed, the Gate consults AbuseIPDB Check and (optionally) VirusTotal,
// combines those external verdicts with the caller's local evidence signal,
// and produces a Decision. The combination rules are intentionally
// conservative:
//
//   - AbuseIPDB is never the sole authority for an "allow" decision. A high
//     AbuseIPDB score never forces escalation by itself — local evidence
//     must also be present (see Decision.Allow / EvaluateConfidence callers
//     and the ActionAllow case in Evaluate).
//   - A 0% AbuseIPDB confidence does not blindly suppress everything: if the
//     local signal is itself confirmed-hostile (e.g. classifier AbuseType
//     exploit_attempt / appsec_attack / confirmed_abuse), the IP is kept in
//     an "investigation_shadow" state — evidence is preserved, but automatic
//     reporting is not triggered without an explicit policy override.
//   - Either provider being unavailable/erroring never blocks the runtime:
//     the Gate falls back to whatever signal is left (the other provider +
//     local evidence) and tags the decision `provider_unavailable`.
//
// # Shadow vs enforce
//
// Evaluate is a pure function: it never performs I/O and never mutates
// anything. All provider calls happen in FetchSignals, which the caller
// invokes once per evaluation. Whether a Decision is actually *applied*
// (report suppressed for real, ban blocked for real, ban executed for real)
// is entirely up to the caller, gated on Policy.Mode. In `shadow` mode the
// caller must only log the Decision; in `enforce` mode the caller applies
// it. This mirrors the existing autoban.Evaluator shadow/live pattern.
package reputation

import (
	"context"
	"net/netip"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/security/quota"
)

// Mode controls whether Decisions are ever applied.
type Mode string

const (
	// ModeShadow computes and logs decisions but guarantees zero mutation
	// anywhere the gate is consulted. This is the safe default.
	ModeShadow Mode = "shadow"
	// ModeEnforce allows callers to apply the gate's decisions.
	ModeEnforce Mode = "enforce"
)

// Action is the gate's recommendation for a given evaluation.
type Action string

const (
	// ActionAllow means the caller's intended operation (report or ban) may
	// proceed, subject to every other pre-existing safety gate the caller
	// already applies (trust registry, dedup, quota, etc). The Gate itself
	// never produces ActionAllow purely from an external signal: local
	// evidence (LocalSignal.Strength != SignalNone) is always required.
	ActionAllow Action = "allow"
	// ActionSuppressLowConfidence means external reputation is low/clean and
	// local evidence is weak: suppress the report/ban entirely, evidence-only.
	ActionSuppressLowConfidence Action = "suppress_low_confidence"
	// ActionInvestigationShadow means external reputation is low/absent but
	// local evidence is confirmed-hostile: keep evidence, do not auto-report
	// or auto-ban without an explicit policy override.
	ActionInvestigationShadow Action = "investigation_shadow"
)

// Reason values written to evidence/telemetry.
const (
	ReasonSuppressedLowReputationConfidence = "suppressed_low_reputation_confidence"
	ReasonInvestigationShadow               = "investigation_shadow"
	ReasonProviderUnavailable               = "provider_unavailable"
	ReasonAllowedCorroborated               = "allowed_corroborated_signal"
)

// SignalStrength classifies the caller's local evidence for this IP.
type SignalStrength string

const (
	// SignalNone means no local evidence at all.
	SignalNone SignalStrength = "none"
	// SignalWeak means local evidence exists but is low-severity (e.g.
	// scanner / benign-adjacent classification, or a single low-confidence
	// hit).
	SignalWeak SignalStrength = "weak"
	// SignalConfirmedHostile means the local classifier assessed this IP as
	// definitively hostile (exploit_attempt, appsec_attack, confirmed_abuse,
	// or an autoban burst/external-burst trigger).
	SignalConfirmedHostile SignalStrength = "confirmed_hostile"
)

// LocalSignal is the caller-supplied summary of local evidence for an IP.
// The Gate never inspects raw events itself — callers (reporting.Service,
// autoban.Evaluator) own classification and pass in their own summary so the
// Gate stays decoupled from classifier/burst-counter internals.
type LocalSignal struct {
	Strength SignalStrength
	// AbuseType is informational (carried into reasons/logs) and does not
	// affect Evaluate's branching beyond what Strength already encodes.
	AbuseType string
}

// ProviderSignal is one provider's verdict, normalized to a 0-100-ish score
// plus an availability flag.
type ProviderSignal struct {
	Available bool
	Score     int // AbuseIPDB confidence (0-100) or VirusTotal malicious-engine count
	Note      string
	Err       error
}

// Signals bundles every external input to Evaluate. Build it once via
// FetchSignals (or by hand in tests).
type Signals struct {
	AbuseIPDB  ProviderSignal
	VirusTotal ProviderSignal
	Local      LocalSignal
}

// Policy holds the thresholds/toggles that drive Evaluate. It is the
// in-package mirror of config.ReputationPolicy — kept separate so this
// package has no dependency on internal/config (avoids import cycles) and
// remains independently testable.
type Policy struct {
	Enabled bool
	Mode    Mode

	AbuseIPDBCheckBeforeReport     bool
	AbuseIPDBMinConfidenceToReport int
	AbuseIPDBMinConfidenceToBan    int
	AbuseIPDBSuppressIfZero        bool

	VirusTotalEnabled       bool
	VirusTotalSuppressClean bool
}

// DefaultPolicy mirrors config.DefaultConfig()'s reputation_policy defaults:
// enabled, but mode is always shadow unless explicitly overridden by config.
func DefaultPolicy() Policy {
	return Policy{
		Enabled: true,
		Mode:    ModeShadow,

		AbuseIPDBCheckBeforeReport:     true,
		AbuseIPDBMinConfidenceToReport: 25,
		AbuseIPDBMinConfidenceToBan:    50,
		AbuseIPDBSuppressIfZero:        true,

		VirusTotalEnabled:       true,
		VirusTotalSuppressClean: true,
	}
}

// Decision is the pure output of Evaluate.
type Decision struct {
	Action Action
	Reason string
	// AllowReport / AllowBan are convenience flags derived from Action and
	// the report-vs-ban thresholds; callers may also branch on Action
	// directly.
	AllowReport bool
	AllowBan    bool
	// ProviderUnavailable is true when at least one consulted provider
	// failed/was skipped (quota, error, disabled). Decisions are still made
	// using whatever signal remained.
	ProviderUnavailable bool
	Shadow              bool // true when Policy.Mode != ModeEnforce
}

// Evaluate is a pure function (no I/O, no mutation) that turns Signals +
// Policy into a Decision. Call FetchSignals to build Signals.
func Evaluate(policy Policy, signals Signals, forBan bool) Decision {
	if !policy.Enabled {
		return Decision{Action: ActionAllow, Reason: "reputation_gate_disabled", AllowReport: true, AllowBan: true, Shadow: policy.Mode != ModeEnforce}
	}

	shadow := policy.Mode != ModeEnforce
	providerUnavailable := !signals.AbuseIPDB.Available || (policy.VirusTotalEnabled && !signals.VirusTotal.Available)

	// Gather whatever scores are actually available. A provider that is
	// unavailable contributes nothing (neither a vote to suppress nor to
	// allow) rather than being treated as a clean/zero verdict.
	haveAbuseIPDB := signals.AbuseIPDB.Available
	abuseScore := signals.AbuseIPDB.Score
	haveVT := policy.VirusTotalEnabled && signals.VirusTotal.Available
	vtMalicious := haveVT && signals.VirusTotal.Score > 0
	vtClean := haveVT && signals.VirusTotal.Score == 0

	minConfidence := policy.AbuseIPDBMinConfidenceToReport
	if forBan {
		minConfidence = policy.AbuseIPDBMinConfidenceToBan
	}

	abuseHigh := haveAbuseIPDB && abuseScore >= minConfidence
	abuseZero := haveAbuseIPDB && abuseScore == 0

	// Strong external signal (AbuseIPDB high OR VirusTotal malicious) only
	// ever escalates when local evidence exists — never from the external
	// signal alone.
	if (abuseHigh || vtMalicious) && signals.Local.Strength != SignalNone {
		return Decision{
			Action:              ActionAllow,
			Reason:              ReasonAllowedCorroborated,
			AllowReport:         true,
			AllowBan:            true,
			ProviderUnavailable: providerUnavailable,
			Shadow:              shadow,
		}
	}

	// Neither provider produced a usable signal (both down/erroring/disabled
	// and not skipped-by-quota-with-the-other-still-tried): fall back to
	// local evidence only. This takes precedence over the
	// SignalConfirmedHostile branch below because there genuinely is no
	// external signal to react to one way or the other — "provider
	// unavailable" must never be confused with "provider says clean".
	if !haveAbuseIPDB && !haveVT {
		allow := signals.Local.Strength == SignalConfirmedHostile
		return Decision{
			Action:              actionFor(allow),
			Reason:              ReasonProviderUnavailable,
			AllowReport:         allow,
			AllowBan:            allow,
			ProviderUnavailable: true,
			Shadow:              shadow,
		}
	}

	// AbuseIPDB low/zero AND VirusTotal clean (when consulted) -> suppress,
	// regardless of local strength being merely "weak". Confirmed-hostile
	// local evidence still escalates to investigation_shadow below, never to
	// a silent suppression, because the local signal alone is real evidence.
	if signals.Local.Strength == SignalConfirmedHostile {
		// Confirmed hostile local payload + non-corroborating external
		// signal (at least one provider responded and did not corroborate):
		// never silently suppress. Keep evidence, mark for investigation, do
		// not auto-report/auto-ban without an explicit policy override (none
		// implemented here intentionally — escalation must be a conscious
		// operator action).
		return Decision{
			Action:              ActionInvestigationShadow,
			Reason:              ReasonInvestigationShadow,
			AllowReport:         false,
			AllowBan:            false,
			ProviderUnavailable: providerUnavailable,
			Shadow:              shadow,
		}
	}

	if policy.AbuseIPDBSuppressIfZero && abuseZero {
		return Decision{
			Action:              ActionSuppressLowConfidence,
			Reason:              ReasonSuppressedLowReputationConfidence,
			AllowReport:         false,
			AllowBan:            false,
			ProviderUnavailable: providerUnavailable,
			Shadow:              shadow,
		}
	}
	if policy.VirusTotalSuppressClean && haveVT && vtClean && !abuseHigh {
		return Decision{
			Action:              ActionSuppressLowConfidence,
			Reason:              ReasonSuppressedLowReputationConfidence,
			AllowReport:         false,
			AllowBan:            false,
			ProviderUnavailable: providerUnavailable,
			Shadow:              shadow,
		}
	}

	// Mixed/inconclusive signal with weak or no local evidence: default to
	// suppression — AbuseIPDB/VirusTotal are never sole authority for an
	// allow, and weak local evidence is not enough on its own either.
	if signals.Local.Strength == SignalNone || signals.Local.Strength == SignalWeak {
		return Decision{
			Action:              ActionSuppressLowConfidence,
			Reason:              ReasonSuppressedLowReputationConfidence,
			AllowReport:         false,
			AllowBan:            false,
			ProviderUnavailable: providerUnavailable,
			Shadow:              shadow,
		}
	}

	return Decision{
		Action:              ActionAllow,
		Reason:              ReasonAllowedCorroborated,
		AllowReport:         true,
		AllowBan:            true,
		ProviderUnavailable: providerUnavailable,
		Shadow:              shadow,
	}
}

func actionFor(allow bool) Action {
	if allow {
		return ActionAllow
	}
	return ActionSuppressLowConfidence
}

// Enricher is the subset of enrichment.Service the Gate needs to fetch
// provider signals. Mirrors autoban.IPEnricher so both packages can share a
// real *enrichment.Service in production and a tiny fake in tests.
type Enricher interface {
	Enrich(ctx context.Context, ip netip.Addr, opts enrichment.LookupOptions) (enrichment.EnrichmentSummary, error)
}

// QuotaChecker is the subset of quota.Registry the Gate needs. Mirrors the
// guard already used in autoban.Evaluator.EvaluateConfidence.
type QuotaChecker interface {
	State(provider string) (quota.State, bool)
}

// FetchSignals calls AbuseIPDB Check (and, if policy.VirusTotalEnabled,
// VirusTotal) explicitly via enricher, respecting quota state exactly like
// autoban.Evaluator's existing guard: if AbuseIPDB quota is Exhausted or
// Throttled, the Check call is skipped and AbuseIPDB is reported as
// unavailable rather than erroring out. Any provider error is likewise
// translated into ProviderSignal.Available=false (fail-open) rather than a
// hard error returned from this function — callers should never treat a
// provider hiccup as a reason to crash or stall.
func FetchSignals(ctx context.Context, enricher Enricher, quotaReg QuotaChecker, ip string, policy Policy, local LocalSignal) Signals {
	signals := Signals{Local: local}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		signals.AbuseIPDB = ProviderSignal{Available: false, Err: err}
		signals.VirusTotal = ProviderSignal{Available: false, Err: err}
		return signals
	}

	quotaConstrained := false
	if quotaReg != nil {
		if state, ok := quotaReg.State("abuseipdb"); ok {
			if state == quota.Exhausted || state == quota.Throttled {
				quotaConstrained = true
				signals.AbuseIPDB = ProviderSignal{Available: false, Note: "abuseipdb_quota_constrained"}
			}
		}
	}

	if !quotaConstrained && enricher != nil {
		summary, err := enricher.Enrich(ctx, addr, enrichment.LookupOptions{ReputationCheck: true})
		if err != nil {
			signals.AbuseIPDB = ProviderSignal{Available: false, Err: err}
		} else {
			signals.AbuseIPDB = extractProviderSignal(summary, "abuseipdb")
			if policy.VirusTotalEnabled {
				signals.VirusTotal = extractProviderSignal(summary, "virustotal")
			}
		}
	} else if policy.VirusTotalEnabled && enricher != nil {
		// AbuseIPDB was skipped (quota) but VirusTotal should still be tried
		// independently — a constrained AbuseIPDB quota must not also starve
		// VirusTotal lookups, since the two providers are billed/limited
		// separately.
		summary, err := enricher.Enrich(ctx, addr, enrichment.LookupOptions{ReputationCheck: true})
		if err != nil {
			signals.VirusTotal = ProviderSignal{Available: false, Err: err}
		} else {
			signals.VirusTotal = extractProviderSignal(summary, "virustotal")
		}
	}

	if !policy.VirusTotalEnabled {
		signals.VirusTotal = ProviderSignal{Available: false, Note: "virustotal_disabled"}
	}

	return signals
}

func extractProviderSignal(summary enrichment.EnrichmentSummary, provider string) ProviderSignal {
	for _, v := range summary.Providers {
		if v.Provider == provider {
			return ProviderSignal{Available: true, Score: v.Score, Note: v.Note}
		}
	}
	return ProviderSignal{Available: false, Note: provider + "_not_returned"}
}

// Gate is a thin, stateful convenience wrapper around Evaluate/FetchSignals
// for callers that want a single method call. It holds no mutation
// authority itself — Decision.Shadow / the caller's own mode check is what
// determines whether anything is actually applied.
type Gate struct {
	Enricher Enricher
	Quota    QuotaChecker
	Policy   Policy
	Now      func() time.Time
}

// NewGate constructs a Gate. enricher and quotaReg may be nil (treated as
// "always unavailable" / "no quota info").
func NewGate(enricher Enricher, quotaReg QuotaChecker, policy Policy) *Gate {
	return &Gate{Enricher: enricher, Quota: quotaReg, Policy: policy, Now: time.Now}
}

// EvaluateReport runs the gate for a pending AbuseIPDB report decision.
func (g *Gate) EvaluateReport(ctx context.Context, ip string, local LocalSignal) Decision {
	signals := FetchSignals(ctx, g.Enricher, g.Quota, ip, g.Policy, local)
	return Evaluate(g.Policy, signals, false)
}

// EvaluateBan runs the gate for a pending Cloudflare ban decision.
func (g *Gate) EvaluateBan(ctx context.Context, ip string, local LocalSignal) Decision {
	signals := FetchSignals(ctx, g.Enricher, g.Quota, ip, g.Policy, local)
	return Evaluate(g.Policy, signals, true)
}
