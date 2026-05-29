package snapshot

import (
	"time"
)

// SnapshotVersion identifies the schema of the snapshot itself.
const SnapshotVersion = 1

// ResourceType defines the logical domain entity captured.
type ResourceType string

const (
	ResourceIPAccessRules ResourceType = "ip_access_rules"
	ResourceLists         ResourceType = "lists"
	ResourceListItems     ResourceType = "list_items"
	ResourceFilters       ResourceType = "filters"
	ResourceRulesets      ResourceType = "rulesets"
	ResourceRulesetRules  ResourceType = "ruleset_rules"
)

// Snapshot is a normalized, provider-agnostic representation of domain state.
// It is the "source of truth" for reconciliation and planning.
type Snapshot struct {
	SnapshotID      string    `json:"snapshot_id"`
	SnapshotVersion int       `json:"snapshot_version"`
	CreatedAt       time.Time `json:"created_at"`

	Source       SnapshotSource `json:"source"`
	ResourceType ResourceType   `json:"resource_type"`

	Scope ScopeMetadata `json:"scope"`

	Pagination PaginationMetadata `json:"pagination"`
	Collection ResourceCollection `json:"collection"`

	Integrity  IntegrityMetadata  `json:"integrity"`
	Provenance ProvenanceMetadata `json:"provenance"`
}

// SnapshotSource describes where the data came from without embedding transport details.
type SnapshotSource struct {
	Provider    string `json:"provider"` // e.g., "cloudflare"
	Endpoint    string `json:"endpoint"` // logical endpoint name
	APIVersion  string `json:"api_version"`
	CaptureMode string `json:"capture_mode"` // "live" | "replay"
}

// ScopeMetadata defines the boundary of the snapshot (sanitized).
type ScopeMetadata struct {
	AccountIDHash string `json:"account_id_hash"`
	ZoneIDHash    string `json:"zone_id_hash"`
	ScopeType     string `json:"scope_type"` // "account" | "zone"
}

// PaginationMetadata captures the history of the discovery process.
type PaginationMetadata struct {
	Paginated        bool     `json:"paginated"`
	PageCount        int      `json:"page_count"`
	TotalExpected    int      `json:"total_expected"`
	TotalObserved    int      `json:"total_observed"`
	SequenceComplete bool     `json:"sequence_complete"`
	CursorChain      []string `json:"cursor_chain,omitempty"`
}

// ResourceCollection contains the actual normalized entities.
type ResourceCollection struct {
	ObjectCount int                `json:"object_count"`
	Objects     []NormalizedObject `json:"objects"`
}

// NormalizedObject is a stable, comparable representation of a resource.
type NormalizedObject struct {
	ObjectID          string         `json:"object_id"` // Provider-specific ID (optional/informational)
	ObjectType        string         `json:"object_type"`
	StableIdentityKey string         `json:"stable_identity_key"` // Domain-controlled unique ID
	Attributes        map[string]any `json:"attributes"`          // Normalized domain attributes
	Metadata          ObjectMetadata `json:"metadata"`
}

// ObjectMetadata carries capture-time details that are not used for diffing.
type ObjectMetadata struct {
	SourcePage    int       `json:"source_page"`
	CapturedAt    time.Time `json:"captured_at"`
	SchemaVersion int       `json:"schema_version"`
}

// IntegrityMetadata ensures the snapshot is tamper-proof and deterministic.
type IntegrityMetadata struct {
	SnapshotChecksum string   `json:"snapshot_checksum"` // Full payload hash
	CanonicalHash    string   `json:"canonical_hash"`    // Hash of normalized objects only
	ObjectHashes     []string `json:"object_hashes"`     // Per-object stable hashes
}

// ProvenanceMetadata tracks the artifact's history for audit and debug.
type ProvenanceMetadata struct {
	FixtureID   string    `json:"fixture_id,omitempty"`
	ReplayID    string    `json:"replay_id,omitempty"`
	GeneratedBy string    `json:"generated_by"`
	GeneratedAt time.Time `json:"generated_at"`
}
