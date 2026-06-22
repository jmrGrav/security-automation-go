// Package trustednetworks implements the hub-and-spoke "Trusted Networks"
// registry: the single source of truth for IP/CIDR entries that should be
// allowed (never banned, never blocked) across both CrowdSec and Cloudflare.
//
// Hub-and-spoke invariant: CrowdSec and Cloudflare are independent spokes.
// The registry pushes to each spoke separately. CrowdSec and Cloudflare must
// never sync directly to each other — every change flows through this
// registry first.
package trustednetworks

import (
	"context"
	"time"
)

// Entry is one trusted network registry record.
type Entry struct {
	// Value is an IP address or CIDR range.
	Value string
	// Label is a short human-readable name (e.g. "Anthropic ASN", "office VPN").
	Label string
	// Source identifies who/what added this entry (e.g. "manual_ui",
	// "protected_networks_import").
	Source string
	// Comment is free-text context, propagated to both spokes.
	Comment   string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Store is the persistence boundary for the trusted networks registry.
// It is the sole source of truth; both spokes are pushed to from this data,
// never read from to reconstruct the registry.
type Store interface {
	List(ctx context.Context) ([]Entry, error)
	Get(ctx context.Context, value string) (Entry, bool, error)
	Upsert(ctx context.Context, e Entry) error
	Remove(ctx context.Context, value string) error
}

// NotePrefix tags every Cloudflare whitelist rule and CrowdSec allowlist
// comment created by this registry, so reconcile/drift logic can identify
// (and only ever touch) entries it owns.
const NotePrefix = "cf-sync:trusted:"
