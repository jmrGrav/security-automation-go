// Package banlifecycle defines the storage contract and recidive-aware
// duration policy for Cloudflare autoban IP access rules.
//
// This package must remain free of dependencies on internal/storage/sqlite
// (the sqlite package depends on this one for the Entry type) and on the
// internal/cloudflare client (the cleanup worker, in the sibling cleanup
// package, depends on small local interfaces instead so it can be tested
// without a real Cloudflare client or a real database).
package banlifecycle

import (
	"context"
	"time"
)

// Status values for Entry.Status.
const (
	StatusActive         = "active"
	StatusExpiredCleaned = "expired_cleaned"
	StatusAutoDebanned   = "auto_debanned"
	StatusManualOverride = "manual_override"
)

// Entry represents one Cloudflare autoban lifecycle record for a single IP.
type Entry struct {
	IP            string
	Source        string // e.g. "autoban_confidence_100", "autoban_burst_malicious"
	Reason        string
	Confidence    int // AbuseIPDB confidence at time of ban, 0 if not applicable
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Duration      time.Duration
	RuleID        string // Cloudflare access rule ID; may be "" if creation response didn't return one
	EvidenceID    string
	RecidiveLevel int    // 1 = first ban, 2 = second, 3+ = third or more
	Status        string // "active", "expired_cleaned", "auto_debanned", "manual_override"
}

// Store persists Cloudflare autoban lifecycle entries.
type Store interface {
	Upsert(ctx context.Context, e Entry) error
	Get(ctx context.Context, ip string) (Entry, bool, error)
	Active(ctx context.Context) ([]Entry, error)
	Expired(ctx context.Context, now time.Time) ([]Entry, error)
	MarkStatus(ctx context.Context, ip string, status string, note string) error
	// Recent returns the most recent entries across all statuses (active,
	// expired_cleaned, auto_debanned, manual_override), newest first, capped
	// at limit. Used to render full lifecycle history, not just current bans.
	Recent(ctx context.Context, limit int) ([]Entry, error)
	// RecidiveLevel returns the count of PRIOR completed (non-active) bans for
	// this IP, for escalation calc. A new ban's RecidiveLevel = this value + 1.
	RecidiveLevel(ctx context.Context, ip string) (int, error)
}

// Default recidive-aware ban durations. RecidiveLevel 1 = first ban,
// 2 = second, 3+ = third-or-more (all bans at level 3+ share the same
// duration).
//
// Escalation is intentionally capped at 24h — there is no week-long (168h)
// tier. Operator decision (2026-06): escalate starting at 1h up to a 24h
// maximum, never beyond. The chosen curve is:
//
//	1st ban (level 1)   ->  1h  (DefaultFirstBanDuration)
//	2nd ban (level 2)   ->  6h  (DefaultSecondBanDuration)
//	3rd+ ban (level 3+) -> 24h  (DefaultThirdPlusBanDuration — hard cap)
//
// The 6h middle step is a deliberate, simple, monotonically increasing
// midpoint between the 1h start and the 24h cap. The operator specified
// only the two endpoints (1h start, 24h ceiling) and left the intermediate
// step(s) to engineering judgement; adjust DefaultSecondBanDuration if a
// different curve is wanted later. No duration produced by this policy may
// ever exceed MaxBanDuration (24h).
const (
	DefaultFirstBanDuration     = 1 * time.Hour
	DefaultSecondBanDuration    = 6 * time.Hour
	DefaultThirdPlusBanDuration = 24 * time.Hour

	// MaxBanDuration is the hard ceiling enforced by DurationFor on every
	// tier, regardless of recidive level or how DurationPolicy was
	// constructed. This guarantees the "never exceed 24h" requirement holds
	// even for an operator-overridden or zero-value DurationPolicy.
	MaxBanDuration = 24 * time.Hour
)

// DurationPolicy maps a recidive level to a ban duration. It is configurable
// so operators can override the defaults without code changes. Regardless of
// the values configured here, DurationFor clamps every result to
// MaxBanDuration (24h) — see that method's doc comment.
type DurationPolicy struct {
	First     time.Duration
	Second    time.Duration
	ThirdPlus time.Duration
}

// DefaultDurationPolicy returns the mission-mandated default durations:
// 1st ban → 1h, 2nd → 6h, 3rd+ → 24h (hard cap, see MaxBanDuration).
func DefaultDurationPolicy() DurationPolicy {
	return DurationPolicy{
		First:     DefaultFirstBanDuration,
		Second:    DefaultSecondBanDuration,
		ThirdPlus: DefaultThirdPlusBanDuration,
	}
}

// DurationFor returns the ban duration for the given recidive level.
// Levels <= 1 use First, level 2 uses Second, level >= 3 uses ThirdPlus. The
// result is always clamped to MaxBanDuration (24h): no recidive level, and
// no operator-configured policy, can ever produce a ban longer than 24h.
func (p DurationPolicy) DurationFor(recidiveLevel int) time.Duration {
	var d time.Duration
	switch {
	case recidiveLevel <= 1:
		d = p.First
	case recidiveLevel == 2:
		d = p.Second
	default:
		d = p.ThirdPlus
	}
	if d > MaxBanDuration {
		return MaxBanDuration
	}
	return d
}
