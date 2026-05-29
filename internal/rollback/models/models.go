package models

import (
	"time"

	"github.com/jm/security-automation-go/internal/reconciliation"
)

type RollbackState string

const (
	StatePlanned     RollbackState = "planned"
	StateValidating  RollbackState = "validating"
	StateExecuting   RollbackState = "executing"
	StateCompleted   RollbackState = "completed"
	StateFailed      RollbackState = "failed"
	StateQuarantined RollbackState = "quarantined"
)

// RollbackBatch represents a collection of compensation operations.
type RollbackBatch struct {
	ID                 string                  `json:"rollback_batch_id"`
	OriginatingBatchID string                  `json:"originating_batch_id"`
	Operations         []CompensationOperation `json:"operations"`
	CreatedAt          time.Time               `json:"created_at"`
	Status             RollbackState           `json:"status"`
	Reason             string                  `json:"reason"`

	// Checkpointing for recovery
	LastCompletedOpIdx int       `json:"last_completed_op_idx"`
	StartedAt          time.Time `json:"started_at,omitempty"`
	FinishedAt         time.Time `json:"finished_at,omitempty"`

	// Coordination
	EpochID      string `json:"epoch_id,omitempty"`
	Generation   int64  `json:"generation,omitempty"`
	LeaseID      string `json:"lease_id,omitempty"`
	FencingToken int64  `json:"fencing_token,omitempty"`
	LeaseAction  string `json:"lease_action,omitempty"`
}

// CompensationOperation is the reverse of a forward mutation.
type CompensationOperation struct {
	OperationID       string                       `json:"operation_id"`
	OriginatingOpID   string                       `json:"originating_op_id"`
	Type              reconciliation.OperationType `json:"type"`
	ResourceType      string                       `json:"resource_type"`
	StableIdentityKey string                       `json:"stable_identity_key"`
	State             RollbackState                `json:"state"`

	// Provider identifiers required for reverse mutation
	ProviderObjectID string `json:"provider_object_id,omitempty"`

	// Data required to undo the change
	Payload any `json:"payload,omitempty"`

	// Preconditions for safe rollback (drift detection)
	ExpectedPrecondition any    `json:"expected_precondition,omitempty"`
	ExpectedETag         string `json:"expected_etag,omitempty"`

	// Result
	ResultID   string    `json:"result_id,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Error      string    `json:"error,omitempty"`

	// Coordination
	ScopeID      string `json:"scope_id,omitempty"`
	LeaseID      string `json:"lease_id,omitempty"`
	FencingToken int64  `json:"fencing_token,omitempty"`
	LeaseAction  string `json:"lease_action,omitempty"`
}

// RollbackPlan is the high-level strategy for a rollback run.
type RollbackPlan struct {
	PlanID           string          `json:"rollback_plan_id"`
	Batches          []RollbackBatch `json:"batches"`
	SnapshotChecksum string          `json:"snapshot_checksum"`
}
