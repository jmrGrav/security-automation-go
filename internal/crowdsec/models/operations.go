package models

import (
	"time"

	"github.com/jm/security-automation-go/internal/snapshot"
)

type ActionType string

const (
	ActionAddDecision    ActionType = "add_decision"
	ActionDeleteDecision ActionType = "delete_decision"
)

// ExecutableOperation represents a concrete CrowdSec action ready for execution or dry-run.
type ExecutableOperation struct {
	ExecutionID       string     `json:"execution_id"`
	Type              ActionType `json:"type"`
	StableIdentityKey string     `json:"stable_identity_key"`

	// Decision details
	Scope    string `json:"scope"` // e.g., "ip", "range"
	Value    string `json:"value"`
	Duration string `json:"duration,omitempty"`
	Reason   string `json:"reason,omitempty"`
	Scenario string `json:"scenario,omitempty"`

	// Metadata for audit and tracing
	OriginatingOpID string                      `json:"originating_op_id"`
	Provenance      snapshot.ProvenanceMetadata `json:"provenance"`
	CreatedAt       time.Time                   `json:"created_at"`
}

// ExecutionSummary provides an operator-visible overview of planned actions.
type ExecutionSummary struct {
	TotalActions int                   `json:"total_actions"`
	Additions    int                   `json:"additions"`
	Deletions    int                   `json:"deletions"`
	Actions      []ExecutableOperation `json:"actions"`
}
