package execution

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/reconciliation"
)

type OperationState string

const (
	StatePlanned          OperationState = "planned"
	StateValidating       OperationState = "validating"
	StateExecuting        OperationState = "executing"
	StateCompleted        OperationState = "completed"
	StateFailed           OperationState = "failed"
	StateRolledBack       OperationState = "rolled_back"
	StateQuarantined      OperationState = "quarantined"
	StateAwaitingApproval OperationState = "awaiting_approval"
)

type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
)

// MutationBatch represents a group of operations to be executed together.
type MutationBatch struct {
	ID               string              `json:"batch_id"`
	ScopeID          string              `json:"scope_id,omitempty"`
	PlanID           string              `json:"plan_id"`
	SnapshotChecksum string              `json:"snapshot_checksum"`
	Operations       []MutationOperation `json:"operations"`
	CreatedAt        time.Time           `json:"created_at"`
	Status           string              `json:"status"` // "pending", "executing", "completed", "failed"

	// Coordination
	EpochID      string `json:"epoch_id,omitempty"`
	Generation   int64  `json:"generation,omitempty"`
	LeaseID      string `json:"lease_id,omitempty"`
	FencingToken int64  `json:"fencing_token,omitempty"`
	LeaseAction  string `json:"lease_action,omitempty"`

	// Derived metrics for policy
	DestructiveCount int `json:"destructive_count,omitempty"`

	ApprovalRequired  bool           `json:"approval_required,omitempty"`
	ApprovalID        string         `json:"approval_id,omitempty"`
	ApprovalStatus    ApprovalStatus `json:"approval_status,omitempty"`
	ApprovalExpiresAt time.Time      `json:"approval_expires_at,omitempty"`
	ApprovedBy        string         `json:"approved_by,omitempty"`
	ApprovalReason    string         `json:"approval_reason,omitempty"`
}

// MutationOperation is a single governed mutation step.
type MutationOperation struct {
	OperationID       string                       `json:"operation_id"`
	ScopeID           string                       `json:"scope_id,omitempty"`
	Type              reconciliation.OperationType `json:"type"`
	ResourceType      string                       `json:"resource_type"`
	StableIdentityKey string                       `json:"stable_identity_key"`
	State             OperationState               `json:"state"`

	// Provider specifics
	ProviderObjectID string `json:"provider_object_id,omitempty"`

	// Preconditions for optimistic concurrency
	ExpectedETag string `json:"expected_etag,omitempty"`

	// Data
	Payload any `json:"payload,omitempty"`

	// Result
	ResultID   string    `json:"result_id,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	Error      string    `json:"error,omitempty"`

	ApprovalRequired  bool           `json:"approval_required,omitempty"`
	ApprovalID        string         `json:"approval_id,omitempty"`
	ApprovalStatus    ApprovalStatus `json:"approval_status,omitempty"`
	ApprovalExpiresAt time.Time      `json:"approval_expires_at,omitempty"`
	ApprovedBy        string         `json:"approved_by,omitempty"`
	ApprovalReason    string         `json:"approval_reason,omitempty"`

	// Coordination
	LeaseID      string `json:"lease_id,omitempty"`
	FencingToken int64  `json:"fencing_token,omitempty"`
	LeaseAction  string `json:"lease_action,omitempty"`
}

func (b MutationBatch) RequiresApprovedExecution(now time.Time) bool {
	if !b.ApprovalRequired {
		return false
	}
	if b.ApprovalStatus != ApprovalApproved {
		return true
	}
	return !b.ApprovalExpiresAt.IsZero() && now.UTC().After(b.ApprovalExpiresAt.UTC())
}

func (op MutationOperation) RequiresApprovedExecution(now time.Time) bool {
	if !op.ApprovalRequired {
		return false
	}
	if op.ApprovalStatus != ApprovalApproved {
		return true
	}
	return !op.ApprovalExpiresAt.IsZero() && now.UTC().After(op.ApprovalExpiresAt.UTC())
}

// ProviderMutator defines the interface for resource-specific mutation logic.
type ProviderMutator interface {
	Execute(op MutationOperation) (string, error)
	DryRun(op MutationOperation) string
}

// ContextProviderMutator is implemented by mutators that can abort in-flight
// provider calls when the execution lease is lost or the parent context is
// cancelled.
type ContextProviderMutator interface {
	ProviderMutator
	ExecuteContext(ctx context.Context, op MutationOperation) (string, error)
}
