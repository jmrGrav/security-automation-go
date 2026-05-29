package models

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/scope"
)

// RuntimeContext is an immutable container for a single execution run.
type RuntimeContext struct {
	context.Context
	Scope        scope.RuntimeScope
	LeaseID      string
	EpochID      string
	FencingToken int64
	TraceID      string
	Budget       TenantBudget
	StartedAt    time.Time
}

// TenantBudget defines operational limits for a tenant.
type TenantBudget struct {
	TenantID             string  `json:"tenant_id"`
	MaxConcurrentWorkers int     `json:"max_concurrent_workers"`
	MaxMutationsPerRun   int     `json:"max_mutations_per_run"`
	MaxRollbacksPerHour  int     `json:"max_rollbacks_per_hour"`
	BurstAllowance       float64 `json:"burst_allowance"`
}

type Priority int

const (
	PriorityNormal   Priority = 0
	PriorityHigh     Priority = 10
	PriorityRollback Priority = 20
)

// WorkItem represents a unit of work for the scheduler.
type WorkItem struct {
	Scope    scope.RuntimeScope
	Priority Priority
	Type     string // "reconcile", "rollback"
}
