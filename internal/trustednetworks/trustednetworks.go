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

// CrowdSecAllowlistStatus is the last known result of the CrowdSec spoke's
// reconcile pass, as persisted by the root-owned cf-allowlist-sync helper
// (the only process with permission to read
// /etc/crowdsec/local_api_credentials.yaml and invoke `cscli allowlists
// ...`). The long-lived cf-sync daemon and the UI never call cscli
// themselves — they only read this record from SQLite.
type CrowdSecAllowlistStatus struct {
	// AllowlistName is the cscli allowlist name this status describes.
	AllowlistName string
	// Configured is true when the helper had a non-empty allowlist name and
	// attempted a sync pass (regardless of outcome). False means the
	// CrowdSec spoke is disabled in config — the helper never ran cscli.
	Configured bool
	// AuthOK is true when the helper's most recent `cscli allowlists
	// inspect` call succeeded (i.e. the helper, running as root, could read
	// local_api_credentials.yaml and reach the local CrowdSec LAPI socket).
	AuthOK bool
	// LastSyncAt is when the helper last completed an attempt (success or
	// failure). Zero value means it has never run.
	LastSyncAt time.Time
	// LastError is the most recent error string, empty on success.
	LastError string
	// DesiredCount is len(registry entries) at the time of the last pass.
	DesiredCount int
	// CurrentCount is the number of entries already present in the remote
	// CrowdSec allowlist at the time of the last pass.
	CurrentCount int
	// DriftCount is the number of remote entries tagged as ours
	// (NotePrefix) but absent from the registry — flagged, never removed.
	DriftCount int
	// Mode echoes the registry's effective mode ("shadow" or "enforce") at
	// the time of the last pass.
	Mode string
}

// CrowdSecStatusStore is the persistence boundary for
// CrowdSecAllowlistStatus. The helper process is the sole writer; the
// daemon and the UI are read-only consumers.
type CrowdSecStatusStore interface {
	GetCrowdSecAllowlistStatus(ctx context.Context, allowlistName string) (CrowdSecAllowlistStatus, bool, error)
	PutCrowdSecAllowlistStatus(ctx context.Context, status CrowdSecAllowlistStatus) error
}
