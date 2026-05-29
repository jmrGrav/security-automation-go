package reconciliation

import (
	"time"

	"github.com/jm/security-automation-go/internal/snapshot"
)

type OperationType string

const (
	OpCreate OperationType = "create"
	OpDelete OperationType = "delete"
	OpUpdate OperationType = "update"
)

type OperationState string

const (
	StatePlanned   OperationState = "planned"
	StateExecuting OperationState = "executing"
	StateCompleted OperationState = "completed"
	StateFailed    OperationState = "failed"
)

// Plan is a serializable, deterministic set of operations derived from
// comparing two snapshots (or a snapshot against an empty state).
// It contains all metadata required to execute and audit the changes.
type Plan struct {
	PlanID         string            `json:"plan_id"`
	SnapshotID     string            `json:"snapshot_id"`
	CreatedAt      time.Time         `json:"created_at"`
	Operations     []Operation       `json:"operations"`
	DriftExpected  bool              `json:"drift_expected"`
	DryRunSummary  string            `json:"dry_run_summary"`
	SafetyMetadata map[string]string `json:"safety_metadata"`
	Status         string            `json:"status"` // e.g., "draft", "approved", "executing", "finalized"
}

// Operation is a single mutation step. It must be idempotent and
// contain enough context to be retried or resumed after failure.
type Operation struct {
	OperationID    string         `json:"operation_id"`
	Type           OperationType  `json:"type"`
	TargetID       string         `json:"target_id"`
	ResourceType   string         `json:"resource_type"`
	Reason         string         `json:"reason"`
	IdempotencyKey string         `json:"idempotency_key"`
	State          OperationState `json:"state"`
	Payload        any            `json:"payload,omitempty"`
	Preconditions  map[string]any `json:"preconditions,omitempty"`
	RollbackData   map[string]any `json:"rollback_data,omitempty"`
	StartedAt      *time.Time     `json:"started_at,omitempty"`
	FinishedAt     *time.Time     `json:"finished_at,omitempty"`
	ErrorMessage   string         `json:"error_message,omitempty"`
}

// Planner is the interface for generating a Plan by comparing snapshots.
type Planner interface {
	Plan(current *snapshot.Snapshot, target []snapshot.NormalizedObject) (*Plan, error)
}
