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
	Reason     string // "confidence_100" or "burst_malicious"
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
	e.burst.Record(ev.IP, ev.Timestamp)
}

// EvaluateConfidence evaluates the confidence-100 rule for ip using AbuseIPDB
// enrichment. Returns a decision without executing any ban — callers should call
// ExecuteBan if ShouldBan is true.
func (e *Evaluator) EvaluateConfidence(ctx context.Context, ip string) BanDecision {
	if skip := e.guardIP(ip, e.now()); skip != "" {
		return BanDecision{IP: ip, SkipReason: skip}
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

	count := e.burst.Count(ip, BurstWindow, e.now())
	if count <= BurstThreshold {
		return BanDecision{IP: ip, SkipReason: "burst_below_threshold"}
	}
	return BanDecision{
		IP:        ip,
		ShouldBan: true,
		Reason:    "burst_malicious",
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
