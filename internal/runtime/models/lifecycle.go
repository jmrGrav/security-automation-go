package models

import (
	"time"
)

type RuntimeStatus string

const (
	StatusIdle             RuntimeStatus = "idle"
	StatusDiscovering      RuntimeStatus = "discovering"
	StatusPlanning         RuntimeStatus = "planning"
	StatusAwaitingApproval RuntimeStatus = "awaiting_approval"
	StatusExecuting        RuntimeStatus = "executing"
	StatusValidating       RuntimeStatus = "validating"
	StatusConverged        RuntimeStatus = "converged"
	StatusRollbackRequired RuntimeStatus = "rollback_required"
	StatusRollingBack      RuntimeStatus = "rolling_back"
	StatusQuarantined      RuntimeStatus = "quarantined"
	StatusFailed           RuntimeStatus = "failed"
	StatusPaused           RuntimeStatus = "paused"
)

// LifecycleState represents the current step in the formal state machine.
type LifecycleState struct {
	Status        RuntimeStatus `json:"status"`
	EpochID       string        `json:"epoch_id,omitempty"`
	RunID         string        `json:"run_id,omitempty"`
	BatchID       string        `json:"batch_id,omitempty"`
	PlanID        string        `json:"plan_id,omitempty"`
	StartedAt     time.Time     `json:"started_at"`
	LastUpdatedAt time.Time     `json:"last_updated_at"`
	Error         string        `json:"error,omitempty"`
	RetryCount    int           `json:"retry_count"`
}

// Transition represents a move between states.
type Transition struct {
	From   RuntimeStatus
	To     RuntimeStatus
	Reason string
}

func (s RuntimeStatus) String() string {
	return string(s)
}
