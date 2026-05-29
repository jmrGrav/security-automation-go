package models

import (
	"time"
)

// Batch represents a collection of operations to be executed atomically or as a logical unit.
type Batch struct {
	ID        string                `json:"batch_id"`
	PlanID    string                `json:"plan_id"`
	Actions   []ExecutableOperation `json:"actions"`
	CreatedAt time.Time             `json:"created_at"`
}

// ExecutionResult captures the outcome of a single operation.
type ExecutionResult struct {
	OperationID string        `json:"operation_id"`
	Status      string        `json:"status"` // "success", "failed", "skipped"
	Duration    time.Duration `json:"duration_ms"`
	Error       string        `json:"error,omitempty"`
	Audit       AuditTrail    `json:"audit"`
}

// AuditTrail provides detailed traceability for a mutation.
type AuditTrail struct {
	Action     ActionType `json:"action"`
	Target     string     `json:"target"`
	RawCommand string     `json:"raw_command"`
	ExecutedAt time.Time  `json:"executed_at"`
	ExecutedBy string     `json:"executed_by"`
}

// BatchResult aggregates the results of an entire batch.
type BatchResult struct {
	BatchID   string            `json:"batch_id"`
	Success   bool              `json:"success"`
	Results   []ExecutionResult `json:"results"`
	StartTime time.Time         `json:"start_time"`
	EndTime   time.Time         `json:"end_time"`
}
