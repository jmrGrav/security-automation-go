// Package enforcementlog defines the storage contract for the real-time
// Cloudflare enforcement event log: one append-only row per ban/deban
// action the daemon actually attempts, success or failure.
//
// banlifecycle.Store tracks current state per IP (one active row, updated
// in place); it cannot represent a failed ExecuteBan call (no entry is ever
// written for those) or render a true history of every attempt. This
// package fills that gap so the /sync UI page can show real enforcement
// activity instead of the retired shadow-cycle comparison log.
//
// Must remain free of dependencies on internal/storage/sqlite, mirroring
// the sibling banlifecycle package.
package enforcementlog

import (
	"context"
	"time"
)

// Action values for Event.Action.
const (
	ActionBanApplied  = "ban_applied"
	ActionBanRemoved  = "ban_removed"
	ActionBanFailed   = "ban_failed"
	ActionDebanFailed = "deban_failed"
)

// Event is one enforcement attempt against Cloudflare: either cfBanExecutor
// creating an access rule (ban_applied / ban_failed) or the banlifecycle
// cleanup worker removing an expired one (ban_removed / deban_failed).
type Event struct {
	ID         int64
	OccurredAt time.Time
	Action     string // ban_applied, ban_removed, ban_failed, deban_failed
	IP         string
	Reason     string
	RuleID     string
	Success    bool
	Error      string        // empty on success
	Duration   time.Duration // wall-clock time the CF API call took
}

// Store persists enforcement events.
type Store interface {
	Append(ctx context.Context, e Event) error
	// Recent returns the most recent events, newest first, capped at limit.
	Recent(ctx context.Context, limit int) ([]Event, error)
	// LastSuccess returns the most recent event with Success=true, if any.
	LastSuccess(ctx context.Context) (Event, bool, error)
	// LastFailure returns the most recent event with Success=false, if any.
	LastFailure(ctx context.Context) (Event, bool, error)
}
