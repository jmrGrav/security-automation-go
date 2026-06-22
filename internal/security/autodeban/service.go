// Package autodeban implements Phase 5 of the reputation-gate mission: a
// periodic scan over banlifecycle.Store's active entries that re-evaluates
// each one through the reputation gate and removes the corresponding
// Cloudflare IP access rule when reputation has genuinely improved (or the
// ban was weak/local-only to begin with) — distinct from, and not a
// duplicate of, the ban-lifecycle task's own expiry-based cleanup worker.
//
// This service NEVER calls Store.Upsert — that write path belongs
// exclusively to the ban-creation flow owned by the parallel ban-lifecycle
// task. It only reads (Active, Get) and updates status (MarkStatus).
package autodeban

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	"github.com/jm/security-automation-go/internal/security/reputation"
	"github.com/jm/security-automation-go/internal/security/trust"
)

// CloudflareDeleter is the subset of *cloudflare.Client needed to remove a
// rule. zoneID is supplied by the Service, not by this interface, so a fake
// can assert on exactly the IDs it was given.
type CloudflareDeleter interface {
	DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error
}

// ReputationGate is the subset of *reputation.Gate this service needs.
type ReputationGate interface {
	EvaluateBan(ctx context.Context, ip string, local reputation.LocalSignal) reputation.Decision
}

// CrowdSecChecker reports whether CrowdSec currently holds an active
// decision for ip. See ActiveDecision doc for the fail-closed contract.
type CrowdSecChecker interface {
	// ActiveDecision returns (true, nil) if CrowdSec has an active decision
	// for ip, (false, nil) if it definitely does not, or a non-nil error if
	// the check could not be performed. Callers must treat a non-nil error
	// the same as "decision present" (fail closed) — see Service.shouldExclude.
	ActiveDecision(ctx context.Context, ip string) (bool, error)
}

// CrowdSecListActiveBans adapts crowdsec.Client.ListActiveBans (a []string
// of banned IPs) to the CrowdSecChecker interface. This is the "best
// available proxy" referenced in the mission brief: there is no cheap
// synchronous "does CrowdSec have a decision for IP X" RPC in this codebase
// (see internal/crowdsec/poller and internal/app/crowdsec_sync_runtime.go —
// both are full-poll/full-sync oriented), so this performs the same
// full-list call the existing CleanupApp uses and checks membership. List
// errors propagate as errors, which Service.shouldExclude treats as
// "decision present" (fail closed) per the mission's explicit instruction
// that wrongly auto-debanning is worse than being conservative here.
type CrowdSecListActiveBans func(ctx context.Context) ([]string, error)

// ActiveDecision implements CrowdSecChecker.
func (f CrowdSecListActiveBans) ActiveDecision(ctx context.Context, ip string) (bool, error) {
	if f == nil {
		// No CrowdSec integration configured at all: unknown, fail closed.
		return false, fmt.Errorf("autodeban: no crowdsec active-ban source configured")
	}
	ips, err := f(ctx)
	if err != nil {
		return false, fmt.Errorf("autodeban: crowdsec active-ban lookup failed: %w", err)
	}
	for _, candidate := range ips {
		if candidate == ip {
			return true, nil
		}
	}
	return false, nil
}

// EvidenceStore is the subset of reporting.EvidenceStore this service needs
// to determine "last local event for this IP" and "recent non-benign event
// for this IP", reusing the exact same query shape (Search with IP+From) for
// both the no-new-events trigger and its inverse (recent-WAF-event
// exclusion).
type EvidenceStore interface {
	Search(ctx context.Context, opts EvidenceSearchOptions) ([]EvidenceRecord, error)
}

// EvidenceSearchOptions mirrors the fields of reporting.EvidenceSearchOptions
// this package needs, kept as a local, narrow type so this package does not
// import internal/services/reporting (avoids a dependency cycle risk and
// keeps autodeban testable without standing up the full reporting stack).
// Production wiring adapts *reporting evidence store via a small shim — see
// cmd/cf-sync wiring.
type EvidenceSearchOptions struct {
	IP   string
	From time.Time
}

// EvidenceRecord mirrors the fields of reporting.DecisionEvidence this
// package needs.
type EvidenceRecord struct {
	Timestamp time.Time
	AbuseType string
}

// AuditSink is the audit trail every deban must write to. Mirrors
// audit.AuditSink so the same sink used elsewhere can be reused.
type AuditSink interface {
	Record(action string, fields map[string]string)
}

// DebanEvidenceWriter records the evidence-side half of every deban.
// Implementations should reuse whatever evidence store the rest of the
// pipeline already writes to (e.g. reporting.EvidenceStore.Append, wrapped).
type DebanEvidenceWriter interface {
	WriteDebanEvidence(ctx context.Context, ip, ruleID, reason, note string, at time.Time) error
}

// Config controls the auto-deban scan.
type Config struct {
	// Enabled mirrors reputation_policy.cloudflare.auto_deban_enabled.
	Enabled bool
	// Mode: shadow (compute + log only, zero mutation) or enforce (delete
	// the Cloudflare rule for real). Defaults to shadow if zero-valued via
	// NewService.
	Mode reputation.Mode
	// NoNewEventsWindow is how long an IP must have produced zero local
	// events before "no recent activity" becomes a deban trigger. Mission
	// default: 24h.
	NoNewEventsWindow time.Duration
	// RecentWAFEventWindow is the lookback window for the "recent
	// WAF/local-attack event exists" hard exclusion. Mission default: 24h
	// (same window, used inverted from NoNewEventsWindow's perspective).
	RecentWAFEventWindow time.Duration
	ZoneID               string
}

// Service performs reputation-triggered early deban scans. It does NOT
// duplicate expiry-based cleanup — that is the parallel cleanup worker's
// job. Service only acts when reputation has genuinely changed, local
// activity has gone quiet, or the ban was weak-signal-only from the start.
type Service struct {
	store    banlifecycle.Store
	gate     ReputationGate
	cf       CloudflareDeleter
	crowdsec CrowdSecChecker
	evidence EvidenceStore
	audit    AuditSink
	debanEvi DebanEvidenceWriter
	trustReg *trust.Registry
	cfg      Config
	now      func() time.Time
	logger   *slog.Logger
}

// NewService constructs a Service. store, gate, cf, crowdsec must not be nil
// for a real (non-test) deployment, but nil-safety is preserved throughout
// (a nil dependency degrades to "exclude/skip" rather than panicking).
func NewService(store banlifecycle.Store, gate ReputationGate, cf CloudflareDeleter, crowdsec CrowdSecChecker, evidence EvidenceStore, auditSink AuditSink, debanEvi DebanEvidenceWriter, trustReg *trust.Registry, cfg Config, logger *slog.Logger) *Service {
	if cfg.Mode == "" {
		cfg.Mode = reputation.ModeShadow
	}
	if cfg.NoNewEventsWindow <= 0 {
		cfg.NoNewEventsWindow = 24 * time.Hour
	}
	if cfg.RecentWAFEventWindow <= 0 {
		cfg.RecentWAFEventWindow = 24 * time.Hour
	}
	return &Service{
		store:    store,
		gate:     gate,
		cf:       cf,
		crowdsec: crowdsec,
		evidence: evidence,
		audit:    auditSink,
		debanEvi: debanEvi,
		trustReg: trustReg,
		cfg:      cfg,
		now:      time.Now,
		logger:   logger,
	}
}

// SetClock overrides the time source for tests.
func (s *Service) SetClock(now func() time.Time) {
	if now != nil {
		s.now = now
	}
}

// ScanResult summarizes one Scan() pass for callers/tests.
type ScanResult struct {
	Considered int
	Debanned   []string
	Excluded   map[string]string // ip -> exclusion reason
	Errors     map[string]string // ip -> error
}

// RecidiveActiveWindowFraction defines "active recidive" for the
// never-auto-deban exclusion: RecidiveLevel >= 2 AND less than this fraction
// of the entry's Duration has elapsed since CreatedAt. The mission brief
// does not pin an exact threshold, so this documents the choice explicitly:
// half the ban duration. An IP that has recidivated at least twice is
// treated as still "hot" for the first half of its current ban window,
// regardless of what reputation providers say in that window — recidivism
// is itself a strong local signal that external reputation can lag behind.
const RecidiveActiveWindowFraction = 0.5

// Scan evaluates every active tracked entry once and debans (or, in shadow
// mode, logs the intent to deban) those that qualify. It is safe to call
// repeatedly on a timer — entries that don't qualify this pass are simply
// skipped again next time.
func (s *Service) Scan(ctx context.Context) ScanResult {
	result := ScanResult{Excluded: map[string]string{}, Errors: map[string]string{}}
	if !s.cfg.Enabled || s.store == nil {
		return result
	}

	entries, err := s.store.Active(ctx)
	if err != nil {
		result.Errors["*"] = "store_active_error: " + err.Error()
		return result
	}

	for _, entry := range entries {
		result.Considered++
		reason, ok := s.evaluateEntry(ctx, entry)
		if !ok {
			result.Excluded[entry.IP] = reason
			continue
		}
		if err := s.deban(ctx, entry, reason); err != nil {
			result.Errors[entry.IP] = err.Error()
			continue
		}
		result.Debanned = append(result.Debanned, entry.IP)
	}
	return result
}

// evaluateEntry returns (triggerReason, true) if entry qualifies for
// reputation-triggered deban, or (exclusionReason, false) otherwise. It
// checks every hard exclusion FIRST (fail closed on any uncertainty), then
// checks the deban triggers.
func (s *Service) evaluateEntry(ctx context.Context, entry banlifecycle.Entry) (string, bool) {
	now := s.now()

	// Hard exclusion: manually protected IP.
	if s.trustReg != nil && len(s.trustReg.MatchIP(entry.IP)) > 0 {
		return "protected_target", false
	}

	// Hard exclusion: rule not tracked by us. Active() only returns entries
	// this store knows about, but re-verify via Get to guard against a
	// Store implementation whose Active() and Get() could ever disagree
	// (e.g. a race with a concurrent MarkStatus/expiry).
	if s.store != nil {
		tracked, found, err := s.store.Get(ctx, entry.IP)
		if err != nil || !found || tracked.RuleID == "" {
			return "unmanaged_rule", false
		}
	}

	// Hard exclusion: active recidive — RecidiveLevel >= 2 AND less than
	// RecidiveActiveWindowFraction of Duration has elapsed since CreatedAt.
	if entry.RecidiveLevel >= 2 && entry.Duration > 0 {
		elapsed := now.Sub(entry.CreatedAt)
		threshold := time.Duration(float64(entry.Duration) * RecidiveActiveWindowFraction)
		if elapsed < threshold {
			return "active_recidive", false
		}
	}

	// Hard exclusion: recent WAF/local-attack event in the lookback window.
	recentHostile, err := s.hasRecentHostileEvent(ctx, entry.IP, now)
	if err != nil {
		// Evidence store unavailable: fail closed on this specific
		// exclusion check too — we cannot positively rule out recent
		// hostile activity, so do not deban.
		return "evidence_check_unavailable", false
	}
	if recentHostile {
		return "recent_waf_event", false
	}

	// Hard exclusion: CrowdSec holds (or might hold — fail closed) an active
	// decision for this IP.
	if csActive, csErr := s.crowdsecActive(ctx, entry.IP); csErr != nil || csActive {
		return "crowdsec_active_or_unknown", false
	}

	// All hard exclusions cleared. Check deban triggers in order.

	// Trigger: no new local events within NoNewEventsWindow.
	lastEvent, hasAny, err := s.lastEventAt(ctx, entry.IP)
	if err == nil && hasAny && now.Sub(lastEvent) >= s.cfg.NoNewEventsWindow {
		return "no_new_events", true
	}
	if err == nil && !hasAny {
		// No local evidence was ever recorded for this IP at all — the ban
		// was, by definition, weak/local-signal-only or external-only.
		return "no_local_evidence_ever", true
	}

	// Trigger: ban was created on weak/local-only grounds (no real
	// corroborating external signal ever) — Reason on the entry records why
	// it was created; treat any non-reputation-corroborated reason as weak.
	if entry.Confidence <= 0 {
		return "weak_signal_ban", true
	}

	// Trigger: re-evaluate via the reputation gate. If it now says
	// AllowBan=false (confidence dropped, or VT now clean), debans.
	if s.gate != nil {
		decision := s.gate.EvaluateBan(ctx, entry.IP, reputation.LocalSignal{Strength: reputation.SignalWeak})
		if !decision.AllowBan {
			return "reputation_dropped:" + decision.Reason, true
		}
	}

	return "still_warranted", false
}

func (s *Service) crowdsecActive(ctx context.Context, ip string) (bool, error) {
	if s.crowdsec == nil {
		// No CrowdSec checker wired at all: unknown, fail closed (treat as
		// active so we never auto-deban without being able to verify).
		return true, fmt.Errorf("autodeban: no crowdsec checker configured")
	}
	return s.crowdsec.ActiveDecision(ctx, ip)
}

func (s *Service) hasRecentHostileEvent(ctx context.Context, ip string, now time.Time) (bool, error) {
	if s.evidence == nil {
		return false, fmt.Errorf("autodeban: no evidence store configured")
	}
	records, err := s.evidence.Search(ctx, EvidenceSearchOptions{IP: ip, From: now.Add(-s.cfg.RecentWAFEventWindow)})
	if err != nil {
		return false, err
	}
	for _, r := range records {
		if !isBenignAbuseType(r.AbuseType) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Service) lastEventAt(ctx context.Context, ip string) (time.Time, bool, error) {
	if s.evidence == nil {
		return time.Time{}, false, fmt.Errorf("autodeban: no evidence store configured")
	}
	// Search with a zero From returns full history for this IP; we only
	// need the most recent timestamp.
	records, err := s.evidence.Search(ctx, EvidenceSearchOptions{IP: ip})
	if err != nil {
		return time.Time{}, false, err
	}
	if len(records) == 0 {
		return time.Time{}, false, nil
	}
	latest := records[0].Timestamp
	for _, r := range records[1:] {
		if r.Timestamp.After(latest) {
			latest = r.Timestamp
		}
	}
	return latest, true, nil
}

func isBenignAbuseType(abuseType string) bool {
	return abuseType == "" || abuseType == "benign_bootstrap" || abuseType == "benign_probe"
}

// deban executes (or, in shadow mode, logs) the deban for entry, always
// writing an audit event and an evidence record with a clear human-readable
// reason regardless of mode.
func (s *Service) deban(ctx context.Context, entry banlifecycle.Entry, triggerReason string) error {
	at := s.now()
	note := fmt.Sprintf("auto-deban: %s (ip=%s rule=%s)", triggerReason, entry.IP, entry.RuleID)
	shadow := s.cfg.Mode != reputation.ModeEnforce

	if s.logger != nil {
		s.logger.Info("autodeban: deban decision", "ip", entry.IP, "rule_id", entry.RuleID, "reason", triggerReason, "shadow", shadow)
	}

	if s.audit != nil {
		fields := map[string]string{
			"ip":      entry.IP,
			"rule_id": entry.RuleID,
			"reason":  triggerReason,
			"shadow":  fmt.Sprintf("%t", shadow),
		}
		s.audit.Record(actionFor(shadow), fields)
	}
	if s.debanEvi != nil {
		if err := s.debanEvi.WriteDebanEvidence(ctx, entry.IP, entry.RuleID, triggerReason, note, at); err != nil && s.logger != nil {
			s.logger.Warn("autodeban: evidence write failed (continuing)", "ip", entry.IP, "error", err)
		}
	}

	if shadow {
		// Shadow mode: decision computed and recorded, but zero mutation —
		// neither the Cloudflare rule nor the store status is touched.
		return nil
	}

	if s.cf == nil {
		return fmt.Errorf("autodeban: no cloudflare deleter configured, cannot enforce deban for %s", entry.IP)
	}
	if entry.RuleID == "" {
		return fmt.Errorf("autodeban: entry for %s has no rule_id, refusing to delete", entry.IP)
	}
	if err := s.cf.DeleteIPAccessRule(ctx, s.cfg.ZoneID, entry.RuleID); err != nil {
		return fmt.Errorf("autodeban: cloudflare delete failed for %s: %w", entry.IP, err)
	}
	if s.store != nil {
		if err := s.store.MarkStatus(ctx, entry.IP, banlifecycle.StatusAutoDebanned, note); err != nil {
			return fmt.Errorf("autodeban: store.MarkStatus failed for %s: %w", entry.IP, err)
		}
	}
	return nil
}

func actionFor(shadow bool) string {
	if shadow {
		return "autodeban.shadow_decision"
	}
	return "autodeban.executed"
}
