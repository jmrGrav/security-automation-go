package health_test

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/health"
)

func newHealthManager(threshold int) *health.HealthManager {
	cb := breaker.New(threshold, 10*time.Second, 30*time.Second)
	return health.New(cb)
}

// TestInitialStatus verifies that a new HealthManager reports "healthy".
func TestInitialStatus_IsHealthy(t *testing.T) {
	hm := newHealthManager(5)
	status := hm.GetStatus()
	if status.Status != "healthy" {
		t.Errorf("expected initial status 'healthy', got %q", status.Status)
	}
	if status.ConsecutiveFails != 0 {
		t.Errorf("expected 0 consecutive fails initially, got %d", status.ConsecutiveFails)
	}
}

// TestOneFailure verifies that a single failure changes status to "degraded".
func TestOneFailure_StatusDegraded(t *testing.T) {
	hm := newHealthManager(5)
	hm.RecordFailure()

	status := hm.GetStatus()
	if status.Status != "degraded" {
		t.Errorf("expected status 'degraded' after one failure, got %q", status.Status)
	}
	if status.ConsecutiveFails != 1 {
		t.Errorf("expected 1 consecutive fail, got %d", status.ConsecutiveFails)
	}
}

// TestSuccessAfterFailure verifies that a success restores status to "healthy".
func TestSuccessAfterFailure_RestoredToHealthy(t *testing.T) {
	hm := newHealthManager(5)
	hm.RecordFailure()
	hm.RecordFailure()
	hm.RecordSuccess()

	status := hm.GetStatus()
	if status.Status != "healthy" {
		t.Errorf("expected status 'healthy' after success, got %q", status.Status)
	}
	if status.ConsecutiveFails != 0 {
		t.Errorf("expected 0 consecutive fails after success, got %d", status.ConsecutiveFails)
	}
}

// TestEnoughFailures_CircuitBreakerOpens verifies that repeated failures open the circuit and status becomes "failing".
func TestEnoughFailures_StatusFailing(t *testing.T) {
	threshold := 3
	hm := newHealthManager(threshold)

	for i := 0; i < threshold; i++ {
		hm.RecordFailure()
	}

	status := hm.GetStatus()
	if status.Status != "failing" {
		t.Errorf("expected status 'failing' after %d failures, got %q", threshold, status.Status)
	}
	if status.BreakerState != breaker.StateOpen {
		t.Errorf("expected breaker state Open, got %v", status.BreakerState)
	}
}

// TestUptimeIncreases verifies that Uptime is a positive duration.
func TestUptime_IsPositive(t *testing.T) {
	hm := newHealthManager(5)
	status := hm.GetStatus()
	if status.Uptime <= 0 {
		t.Errorf("expected positive uptime, got %v", status.Uptime)
	}
}
