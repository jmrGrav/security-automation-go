package stateful_test

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/scheduler/stateful"
)

// TestRetryPolicy_ZeroAttemptReturnsInitialDelay verifies that attempt=0
// returns the InitialDelay without any backoff multiplication.
func TestRetryPolicy_ZeroAttemptReturnsInitialDelay(t *testing.T) {
	p := stateful.RetryPolicy{
		InitialDelay: 5 * time.Second,
		MaxDelay:     10 * time.Minute,
		Multiplier:   2.0,
		Jitter:       0,
		MaxRetries:   3,
	}
	d := p.CalculateDelay(0)
	if d != 5*time.Second {
		t.Errorf("attempt=0: want 5s, got %v", d)
	}
}

// TestRetryPolicy_ExponentialGrowth verifies the delay grows on each attempt.
func TestRetryPolicy_ExponentialGrowth(t *testing.T) {
	p := stateful.RetryPolicy{
		InitialDelay: 1 * time.Second,
		MaxDelay:     1 * time.Hour,
		Multiplier:   2.0,
		Jitter:       0,
		MaxRetries:   10,
	}

	var prev time.Duration
	for attempt := 1; attempt <= 5; attempt++ {
		d := p.CalculateDelay(attempt)
		if d <= prev && attempt > 1 {
			t.Errorf("attempt=%d: expected delay > %v, got %v (not growing)", attempt, prev, d)
		}
		prev = d
	}
}

// TestRetryPolicy_CappedAtMaxDelay verifies the delay never exceeds MaxDelay.
func TestRetryPolicy_CappedAtMaxDelay(t *testing.T) {
	p := stateful.RetryPolicy{
		InitialDelay: 1 * time.Second,
		MaxDelay:     10 * time.Second,
		Multiplier:   10.0,
		Jitter:       0,
	}
	for attempt := 1; attempt <= 20; attempt++ {
		d := p.CalculateDelay(attempt)
		if d > p.MaxDelay {
			t.Errorf("attempt=%d: delay %v exceeds MaxDelay %v", attempt, d, p.MaxDelay)
		}
	}
}

// TestRetryPolicy_DefaultPolicy verifies the default policy has sensible values.
func TestRetryPolicy_DefaultPolicy(t *testing.T) {
	p := stateful.DefaultRetryPolicy()
	if p.InitialDelay <= 0 {
		t.Error("default InitialDelay must be positive")
	}
	if p.MaxDelay <= p.InitialDelay {
		t.Error("default MaxDelay must exceed InitialDelay")
	}
	if p.Multiplier <= 1.0 {
		t.Error("default Multiplier must be > 1 for backoff")
	}
	if p.MaxRetries <= 0 {
		t.Error("default MaxRetries must be positive")
	}
}

// TestCooldownPolicy_DefaultValues verifies default cooldown durations are sane.
func TestCooldownPolicy_DefaultValues(t *testing.T) {
	p := stateful.DefaultCooldownPolicy()
	if p.RollbackDelay <= 0 {
		t.Error("RollbackDelay must be positive")
	}
	if p.OscillationDelay <= 0 {
		t.Error("OscillationDelay must be positive")
	}
	if p.BreakerOpenDelay <= 0 {
		t.Error("BreakerOpenDelay must be positive")
	}
	if p.ConvergenceDelay <= 0 {
		t.Error("ConvergenceDelay must be positive")
	}
	// Oscillation delay should be the longest — major circuit protection
	if p.OscillationDelay < p.RollbackDelay {
		t.Error("OscillationDelay should be >= RollbackDelay (longer protection window)")
	}
}
