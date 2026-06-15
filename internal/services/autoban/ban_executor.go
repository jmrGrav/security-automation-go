package autoban

import "context"

// BanExecutor applies a confirmed ban decision to an external enforcement system.
// When nil, decisions are logged but not enforced (shadow mode behaviour).
type BanExecutor interface {
	// ExecuteBan enacts the ban for decision.IP. Returns nil on success.
	// Callers should only invoke RecordBan after a successful ExecuteBan to
	// preserve retry semantics on transient failures.
	ExecuteBan(ctx context.Context, decision BanDecision) error
}
