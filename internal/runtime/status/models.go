package status

import (
	"time"

	"github.com/jm/security-automation-go/internal/runtime/breaker"
)

// RuntimeStatus is a complete, sanitized view of the system state.
type RuntimeStatus struct {
	Version   string    `json:"version"`
	StartedAt time.Time `json:"started_at"`
	Uptime    string    `json:"uptime"`

	Health         HealthStatus         `json:"health"`
	Breaker        BreakerStatus        `json:"breaker"`
	Lock           LockStatus           `json:"lock"`
	Reconciliation ReconciliationStatus `json:"reconciliation"`
	Quarantine     QuarantineStatus     `json:"quarantine"`
}

type HealthStatus struct {
	Status           string `json:"status"` // healthy, degraded, failing
	ConsecutiveFails int    `json:"consecutive_fails"`
	LastSuccess      string `json:"last_success_at,omitempty"`
	LastFailure      string `json:"last_failure_at,omitempty"`
}

type BreakerStatus struct {
	State        string `json:"state"`
	FailureCount int    `json:"failure_count"`
	Threshold    int    `json:"threshold"`
}

type LockStatus struct {
	IsLocked bool `json:"is_locked"`
	PID      int  `json:"owner_pid,omitempty"`
}

type ReconciliationStatus struct {
	LastRunAt           string `json:"last_run_at,omitempty"`
	LastSuccessAt       string `json:"last_success_at,omitempty"`
	LastAppliedSnapshot string `json:"last_applied_snapshot_checksum,omitempty"`
	LastPlanID          string `json:"last_plan_id,omitempty"`
	DriftDetected       bool   `json:"drift_detected"`
}

type QuarantineStatus struct {
	ActiveItems int    `json:"active_items"`
	LastReason  string `json:"last_quarantine_reason,omitempty"`
}

// MapBreakerState converts the internal state enum to a string.
func MapBreakerState(s breaker.State) string {
	switch s {
	case breaker.StateClosed:
		return "closed"
	case breaker.StateOpen:
		return "open"
	case breaker.StateHalfOpen:
		return "half-open"
	default:
		return "unknown"
	}
}
