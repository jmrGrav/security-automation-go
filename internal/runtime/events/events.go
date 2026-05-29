package events

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

type Category string

const (
	CategoryLifecycle Category = "lifecycle"
	CategoryPolicy    Category = "policy"
	CategoryMutation  Category = "mutation"
	CategoryRollback  Category = "rollback"
	CategoryDrift     Category = "drift"
	CategoryScheduler Category = "scheduler"
	CategoryLease     Category = "lease"
	CategoryFencing   Category = "fencing"
	CategoryHA        Category = "ha"
	CategorySecurity  Category = "security"
)

const (
	SchemaVersion = 1
)

type Event struct {
	ID            int64           `json:"id"`  // Database-generated sequence
	Sequence      uint64          `json:"seq"` // Logical sequence per scope
	UID           string          `json:"event_uid,omitempty"`
	Timestamp     time.Time       `json:"ts"`
	Category      Category        `json:"category"`
	Type          string          `json:"type"`
	CorrelationID string          `json:"correlation_id"` // Links related events (e.g. RunID)
	CausalID      string          `json:"causal_id"`      // Link to the event that triggered this one
	Actor         string          `json:"actor"`
	ScopeID       string          `json:"scope_id"`
	Payload       json.RawMessage `json:"payload"`
	Metadata      map[string]any  `json:"metadata,omitempty"`
}

type PublishRequest struct {
	UID           string
	Timestamp     time.Time
	Category      Category
	Type          string
	CorrelationID string
	CausalID      string
	Actor         string
	ScopeID       string
	Payload       any
	Metadata      map[string]any
}

type Checkpoint struct {
	Name          string          `json:"name"`
	ScopeID       string          `json:"scope_id"`
	Sequence      uint64          `json:"sequence"`
	EventID       int64           `json:"event_id"`
	Checksum      string          `json:"checksum"`
	State         json.RawMessage `json:"state"`
	Metadata      map[string]any  `json:"metadata,omitempty"`
	SchemaVersion int             `json:"schema_version"`
	CreatedAt     time.Time       `json:"created_at"`
}

var ErrCheckpointNotFound = errors.New("runtime checkpoint not found")

// Payload types
type LifecycleTransition struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

type PolicyDecision struct {
	PolicyID string `json:"policy_id"`
	Action   string `json:"action"`
	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

type Mutation struct {
	Action string `json:"action"`
	Target string `json:"target"`
	Status string `json:"status"`
}

type DriftDetection struct {
	Target string `json:"target"`
	Diff   string `json:"diff"`
}

type HAResourceEvent struct {
	Resource string `json:"resource"`
	Event    string `json:"event"` // e.g. "leader_elected", "lease_acquired"
}

type EventStore interface {
	Append(ctx context.Context, event *Event) error
	List(ctx context.Context, scopeID string, afterSequence uint64) ([]Event, error)
	GetLastSequence(ctx context.Context, scopeID string) (uint64, error)
}

type CheckpointStore interface {
	SaveCheckpoint(ctx context.Context, checkpoint Checkpoint) error
	LatestCheckpoint(ctx context.Context, scopeID string, name string) (Checkpoint, error)
	ListCheckpoints(ctx context.Context, scopeID string, name string, limit int) ([]Checkpoint, error)
	DeleteCheckpoint(ctx context.Context, scopeID string, name string, sequence uint64) error
}
