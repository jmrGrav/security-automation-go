// Package banlifecycle defines the Entry/Store shape used to track
// Cloudflare bans that security-automation-go itself created, so they can be
// expired/cleaned-up/auto-debanned later.
//
// NOTE — reconciliation required: this is a local copy of an interface being
// built concurrently by a parallel task (M1 Phase 2, "Cloudflare ban
// lifecycle store + cleanup worker"). The shape below is specified verbatim
// by the mission brief for this task and MUST be byte-for-byte compatible
// with whatever the parallel task lands at
// internal/cloudflare/banlifecycle. When that package exists in the
// integration branch, DELETE this copy and re-point every import in
// internal/security/autodeban at the real package — the two are designed to
// be a drop-in swap (same package name, same exported names, same method
// signatures).
//
// This task (the reputation gate / auto-deban) only ever calls Active, Get,
// and MarkStatus — never Upsert, which belongs exclusively to the
// ban-creation path the parallel task owns.
package banlifecycle

import (
	"context"
	"time"
)

// Entry is one tracked Cloudflare ban.
type Entry struct {
	IP            string
	Source        string
	Reason        string
	Confidence    int
	CreatedAt     time.Time
	ExpiresAt     time.Time
	Duration      time.Duration
	RuleID        string
	EvidenceID    string
	RecidiveLevel int
	Status        string // "active", "expired_cleaned", "auto_debanned", "manual_override"
}

// Status values. Mirrors the comment on Entry.Status above; defined as
// constants here for callers in this package's consumers.
const (
	StatusActive         = "active"
	StatusExpiredCleaned = "expired_cleaned"
	StatusAutoDebanned   = "auto_debanned"
	StatusManualOverride = "manual_override"
)

// Store is the persistence interface for tracked ban entries.
type Store interface {
	Upsert(ctx context.Context, e Entry) error
	Get(ctx context.Context, ip string) (Entry, bool, error)
	Active(ctx context.Context) ([]Entry, error)
	Expired(ctx context.Context, now time.Time) ([]Entry, error)
	MarkStatus(ctx context.Context, ip string, status string, note string) error
	RecidiveLevel(ctx context.Context, ip string) (int, error)
}
