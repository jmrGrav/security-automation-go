package breaker

import (
	"testing"
	"time"
)

func TestCircuitBreaker(t *testing.T) {
	cb := New(2, time.Minute, 100*time.Millisecond)

	// 1. Initially closed
	if !cb.Allow() {
		t.Error("should allow when closed")
	}

	// 2. Record failures
	cb.RecordFailure()
	if !cb.Allow() {
		t.Error("should still allow after 1 failure (threshold 2)")
	}

	cb.RecordFailure()
	if cb.Allow() {
		t.Error("should not allow after 2 failures")
	}
	if cb.GetState() != StateOpen {
		t.Errorf("expected StateOpen, got %v", cb.GetState())
	}

	// 3. Wait for reset timeout
	time.Sleep(150 * time.Millisecond)
	if !cb.Allow() {
		t.Error("should allow after reset timeout (half-open)")
	}
	if cb.GetState() != StateHalfOpen {
		t.Errorf("expected StateHalfOpen, got %v", cb.GetState())
	}

	// 4. Success closes it
	cb.RecordSuccess()
	if cb.GetState() != StateClosed {
		t.Errorf("expected StateClosed, got %v", cb.GetState())
	}
}
