package models

import (
	"time"

	"github.com/jm/security-automation-go/internal/runtime/breaker"
)

// HealthStatus represents the high-level operational state of the daemon.
type HealthStatus struct {
	Status           string        `json:"status"` // "healthy", "degraded", "failing"
	LastSuccess      time.Time     `json:"last_success_at"`
	LastFailure      time.Time     `json:"last_failure_at"`
	ConsecutiveFails int           `json:"consecutive_fails"`
	BreakerState     breaker.State `json:"breaker_state"`
	Uptime           time.Duration `json:"uptime_ms"`
}

// Metrics tracks basic internal counters for observability.
type Metrics struct {
	RunsTotal       int64 `json:"runs_total"`
	RunsFailed      int64 `json:"runs_failed"`
	OperationsTotal int64 `json:"operations_total"`
	MutationsTotal  int64 `json:"mutations_total"`
	BreakerOpens    int64 `json:"breaker_opens"`
	KillSwitchHits  int64 `json:"kill_switch_hits"`
}

// EventType standardizes internal signals.
type EventType string

const (
	EventRunStarted     EventType = "run_started"
	EventPlanGenerated  EventType = "plan_generated"
	EventBatchExecuting EventType = "batch_executing"
	EventRunCompleted   EventType = "run_completed"
	EventRunFailed      EventType = "run_failed"
	EventBreakerState   EventType = "breaker_state_changed"
	EventQuarantined    EventType = "item_quarantined"
)

// SystemEvent is a structured internal event for the bus.
type SystemEvent struct {
	Type      EventType              `json:"event"`
	Timestamp time.Time              `json:"ts"`
	RunID     string                 `json:"run_id,omitempty"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
}
