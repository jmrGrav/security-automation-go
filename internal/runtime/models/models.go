package models

import (
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

type RunStatus string

const (
	RunStatusStarted   RunStatus = "started"
	RunStatusExecuting RunStatus = "executing"
	RunStatusCompleted RunStatus = "completed"
	RunStatusFailed    RunStatus = "failed"
)

// Run represents a single end-to-end execution of the pipeline.
type Run struct {
	RunID      string    `json:"run_id"`
	StartTime  time.Time `json:"start_time"`
	Status     RunStatus `json:"status"`
	SnapshotID string    `json:"snapshot_id,omitempty"`
	PlanID     string    `json:"plan_id,omitempty"`
}

// AuditEvent is a single entry in the JSONL journal.
type AuditEvent struct {
	Timestamp time.Time              `json:"ts"`
	RunID     string                 `json:"run_id"`
	BatchID   string                 `json:"batch_id,omitempty"`
	OpID      string                 `json:"op_id,omitempty"`
	Status    string                 `json:"status"` // "started", "executing", "completed", "failed", "idempotent"
	Action    models.ActionType      `json:"action,omitempty"`
	Target    string                 `json:"target,omitempty"`
	Duration  int64                  `json:"duration_ms,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}

// RuntimeState tracks the "last known good" state across restarts.
type RuntimeState struct {
	LastRunID           string    `json:"last_run_id"`
	LastAppliedSnapshot string    `json:"last_applied_snapshot_checksum"`
	LastPlanID          string    `json:"last_plan_id"`
	LastSuccessAt       time.Time `json:"last_success_at"`
	IncompleteBatchID   string    `json:"incomplete_batch_id,omitempty"`
	ActiveRollbackID    string    `json:"active_rollback_id,omitempty"`

	// Coordination extensions
	CurrentEpoch        Epoch  `json:"current_epoch"`
	ActiveLease         *Lease `json:"active_lease,omitempty"`
	ActiveRollbackLease *Lease `json:"active_rollback_lease,omitempty"`
	LastSafeCheckpoint  string `json:"last_safe_checkpoint,omitempty"`

	// Lifecycle extensions
	Lifecycle LifecycleState `json:"lifecycle"`

	// Cooldown extensions
	Cooldowns map[string]time.Time `json:"cooldowns,omitempty"`
}
