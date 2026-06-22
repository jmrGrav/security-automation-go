// Package autoban evaluates Cloudflare auto-ban rules derived from AbuseIPDB
// enrichment and malicious event burst counters.
//
// # Safety constraints (never relaxed)
//
//   - Only public/global-unicast IPs are eligible for banning.
//   - Trust registry match (RFC1918, loopback, link-local, Cloudflare IP ranges,
//     operator-configured protected resources) prevents any ban.
//   - Dedup window prevents repeated bans for the same IP.
//   - In shadow/dry-run mode (cfg.Cloudflare.MutationsEnabled == false or
//     cfg.Cloudflare.AutoBanEnabled == false) the evaluator only logs and records
//     shadow evidence — it never mutates Cloudflare.
//
// # Quota safety
//
// AbuseIPDB enrichment is only triggered for IPs that passed the malicious-event
// gate (not suppressed as benign, not protected). The enrichment service's 6-hour
// cache ensures the Check API is called at most once per IP per 6-hour window.
package autoban

import (
	"context"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/security/quota"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/trust"
)

const (
	BurstWindow    = 30 * time.Second
	BurstThreshold = 30 // > 30 triggers ban
	BanDedupTTL    = 24 * time.Hour
)

// IPEnricher is the subset of enrichment.Service used by the evaluator.
type IPEnricher interface {
	Enrich(ctx context.Context, ip netip.Addr, opts enrichment.LookupOptions) (enrichment.EnrichmentSummary, error)
}

// BanDecision records the result of a ban evaluation for one IP.
type BanDecision struct {
	IP         string
	ShouldBan  bool
	Reason     string // "confidence_100", "burst_malicious", or "http_error_burst"
	SkipReason string // non-empty when skipped
	Shadow     bool   // true when live mutations are disabled
}

// MaliciousEvent is a stripped-down record of a detected malicious event.
type MaliciousEvent struct {
	IP        string
	Timestamp time.Time
	// AbuseType is the classifier's assessment (e.g. "scanner", "brute_force").
	// Must not be "benign_bootstrap" or "benign_probe" for the event to count.
	AbuseType string
	// RayID is the Cloudflare ray identifier used to deduplicate events across
	// replay-overlap polls. Empty string disables dedup for this event.
	RayID string
}

// Evaluator evaluates auto-ban rules against incoming malicious events.
type Evaluator struct {
	trust    *trust.Registry
	enricher IPEnricher
	burst    *BurstCounter
	dedup    *BanDedup
	logger   *slog.Logger
	liveMode bool // true = CF mutations allowed
	now      func() time.Time

	// reputationGate, when set, is consulted as an ADDITIONAL restriction
	// after every other existing safety guard (guardIP, local evidence,
	// quota) has already allowed a ban. It can only turn a ShouldBan=true
	// decision into false (or into a shadow no-op) — it must never relax any
	// pre-existing gate. A nil gate (the default) leaves EvaluateConfidence
	// and EvaluateBurst behaving exactly as before this field existed.
	reputationGate ReputationGate
}

// ReputationGate is the subset of *reputation.Gate the evaluator needs.
type ReputationGate interface {
	EvaluateBan(ctx context.Context, ip string, local reputation.LocalSignal) reputation.Decision
}

// SetReputationGate wires the cross-provider reputation gate
// (internal/security/reputation) as an additional ban restriction. Pass nil
// to disable (the default).
func (e *Evaluator) SetReputationGate(gate ReputationGate) {
	e.reputationGate = gate
}

// Config holds the options for NewEvaluator.
type Config struct {
	// LiveMode must be true for bans to take effect. When false the evaluator
	// operates in shadow mode: it evaluates rules and logs decisions but never
	// calls Cloudflare. Set to cfg.Cloudflare.MutationsEnabled && cfg.Cloudflare.AutoBanEnabled.
	LiveMode bool
}

// NewEvaluator constructs an Evaluator. trust and enricher must not be nil.
func NewEvaluator(cfg Config, trustReg *trust.Registry, enricher IPEnricher, logger *slog.Logger) *Evaluator {
	return &Evaluator{
		trust:    trustReg,
		enricher: enricher,
		burst:    NewBurstCounter(),
		dedup:    NewBanDedup(BanDedupTTL),
		logger:   logger,
		liveMode: cfg.LiveMode,
		now:      time.Now,
	}
}

// RecordMalicious feeds a malicious event into the burst counter. Only call
// for events where AbuseType is definitively non-benign (not benign_bootstrap
// or benign_probe) and the IP is not suppressed as protected_target.
func (e *Evaluator) RecordMalicious(ev MaliciousEvent) {
	if ev.IP == "" || isBenign(ev.AbuseType) {
		return
	}
	if _, err := netip.ParseAddr(ev.IP); err != nil {
		return
	}
	e.burst.Record(ev.IP, ev.RayID, ev.Timestamp)
}

// EvaluateConfidence evaluates the confidence-100 rule for ip using AbuseIPDB
// enrichment. Returns a decision without executing any ban — callers should call
// ExecuteBan if ShouldBan is true.
func (e *Evaluator) EvaluateConfidence(ctx context.Context, ip string) BanDecision {
	if skip := e.guardIP(ip, e.now()); skip != "" {
		return BanDecision{IP: ip, SkipReason: skip}
	}

	// Require local evidence: at least one malicious event for this IP must have
	// been observed locally (CF WAF replay) before consulting AbuseIPDB. This
	// prevents banning IPs that hold a high external score but have never appeared
	// in local traffic — a necessary guard against false positives.
	if !e.burst.HasLocalEvidence(ip, e.now()) {
		return BanDecision{IP: ip, SkipReason: "no_local_evidence"}
	}

	// Guard: skip Check API call when AbuseIPDB quota is exhausted or throttled.
	// This prevents spending the shared daily Check+Report budget during scan storms.
	if state, ok := quota.DefaultRegistry().State("abuseipdb"); ok {
		if state == quota.Exhausted || state == quota.Throttled {
			return BanDecision{IP: ip, SkipReason: "abuseipdb_quota_constrained"}
		}
	}

	addr, _ := netip.ParseAddr(ip)
	summary, err := e.enricher.Enrich(ctx, addr, enrichment.LookupOptions{ManualForensics: true})
	if err != nil {
		return BanDecision{IP: ip, SkipReason: "enrichment_error: " + err.Error()}
	}

	score := abuseIPDBScore(summary)
	if score < 100 {
		return BanDecision{IP: ip, SkipReason: "confidence_below_100"}
	}
	// Reputation gate: ADDITIONAL restriction on top of every guard above.
	// Local evidence is already confirmed (HasLocalEvidence, just above), so
	// this is evaluated as a confirmed-hostile local signal — the gate can
	// only tighten this decision further, never loosen it.
	if skip := e.reputationSkip(ctx, ip, reputation.LocalSignal{Strength: reputation.SignalConfirmedHostile}); skip != "" {
		return BanDecision{IP: ip, SkipReason: skip}
	}
	return BanDecision{
		IP:        ip,
		ShouldBan: true,
		Reason:    "confidence_100",
		Shadow:    !e.liveMode,
	}
}

// EvaluateBurst evaluates the burst rule for ip using the in-memory counter.
func (e *Evaluator) EvaluateBurst(ip string) BanDecision {
	if skip := e.guardIP(ip, e.now()); skip != "" {
		return BanDecision{IP: ip, SkipReason: skip}
	}

	if !e.burst.DetectBurst(ip, BurstWindow, BurstThreshold, e.now()) {
		return BanDecision{IP: ip, SkipReason: "burst_below_threshold"}
	}
	// Reputation gate: ADDITIONAL restriction. A burst above BurstThreshold
	// is itself confirmed-hostile local evidence (RecordMalicious already
	// filters out benign AbuseType values), so the gate is given
	// SignalConfirmedHostile — it can only block this further (e.g. if both
	// providers actively contradict it), never relax the burst threshold
	// itself. context.Background() is used here because EvaluateBurst's
	// public signature predates context-awareness and changing it would
	// ripple through every existing caller/test for no safety benefit: the
	// gate already fails open on any error/timeout.
	if skip := e.reputationSkip(context.Background(), ip, reputation.LocalSignal{Strength: reputation.SignalConfirmedHostile}); skip != "" {
		return BanDecision{IP: ip, SkipReason: skip}
	}
	return BanDecision{
		IP:        ip,
		ShouldBan: true,
		Reason:    "burst_malicious",
		Shadow:    !e.liveMode,
	}
}

// reputationSkip consults the reputation gate (if configured) and returns a
// non-empty skip reason when the gate's decision is a real (non-shadow)
// suppression. It never returns a skip reason when the gate is nil, when the
// gate is in shadow mode (decision is logged only), or when the gate allows
// the ban — in every such case the pre-existing decision stands unchanged.
func (e *Evaluator) reputationSkip(ctx context.Context, ip string, local reputation.LocalSignal) string {
	if e.reputationGate == nil {
		return ""
	}
	decision := e.reputationGate.EvaluateBan(ctx, ip, local)
	if e.logger != nil {
		e.logger.Debug("autoban: reputation gate decision",
			"ip", ip, "action", decision.Action, "reason", decision.Reason,
			"shadow", decision.Shadow, "provider_unavailable", decision.ProviderUnavailable)
	}
	if decision.Shadow {
		return ""
	}
	if !decision.AllowBan {
		return "reputation_gate:" + decision.Reason
	}
	return ""
}

// EvaluateExternalBurst authorizes a ban for ip on behalf of a caller that has
// already aggregated its own significance signal (e.g. an HTTP-error burst
// counted by an unrelated polling window). It does not consult this
// evaluator's internal burst counter — callers own their own threshold
// decision — but it still applies every standard safety guard (public IP
// only, trust-registry protection, dedup, shadow mode) via guardIP, so a
// caller can never bypass those guarantees just because its signal source
// is different.
func (e *Evaluator) EvaluateExternalBurst(ip, reason string) BanDecision {
	if skip := e.guardIP(ip, e.now()); skip != "" {
		return BanDecision{IP: ip, SkipReason: skip}
	}
	return BanDecision{
		IP:        ip,
		ShouldBan: true,
		Reason:    reason,
		Shadow:    !e.liveMode,
	}
}

// guardIP runs all IP safety checks. Returns a non-empty skip reason if the IP
// must not be banned, or "" if it is eligible.
func (e *Evaluator) guardIP(ip string, now time.Time) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return "invalid_ip"
	}
	if !addr.IsValid() || !addr.IsGlobalUnicast() || addr.IsPrivate() {
		return "not_public_ip"
	}
	if e.trust != nil && len(e.trust.MatchIP(ip)) > 0 {
		return "protected_target"
	}
	if e.dedup.AlreadyBanned(ip, now) {
		return "already_banned"
	}
	return ""
}

// RecordBan marks ip as banned in the dedup store. Call after a successful ban execution.
func (e *Evaluator) RecordBan(ip string) {
	e.dedup.MarkBanned(ip, e.now())
}

// Log emits a structured log line for a ban decision.
func (e *Evaluator) Log(decision BanDecision) {
	if e.logger == nil {
		return
	}
	if !decision.ShouldBan {
		if decision.SkipReason != "" {
			e.logger.Debug("autoban: ip skipped", "ip", decision.IP, "reason", decision.SkipReason)
		}
		return
	}
	level := slog.LevelInfo
	if decision.Shadow {
		level = slog.LevelInfo
	}
	e.logger.Log(context.Background(), level, "autoban: ban decision",
		"ip", decision.IP,
		"reason", decision.Reason,
		"shadow", decision.Shadow,
		"live_mode", e.liveMode,
	)
}

// isBenign returns true for AbuseType values that should never increment the burst counter.
func isBenign(abuseType string) bool {
	return abuseType == "benign_bootstrap" || abuseType == "benign_probe" || abuseType == ""
}

// abuseIPDBScore extracts the AbuseIPDB confidence score from an enrichment summary.
func abuseIPDBScore(s enrichment.EnrichmentSummary) int {
	for _, v := range s.Providers {
		if v.Provider == "abuseipdb" {
			return v.Score
		}
	}
	return 0
}
