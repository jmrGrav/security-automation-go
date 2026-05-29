package health

import (
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

type HealthManager struct {
	mu sync.RWMutex

	startTime        time.Time
	lastSuccess      time.Time
	lastFailure      time.Time
	consecutiveFails int

	breaker *breaker.CircuitBreaker
}

func New(cb *breaker.CircuitBreaker) *HealthManager {
	return &HealthManager{
		startTime: time.Now(),
		breaker:   cb,
	}
}

func (h *HealthManager) RecordSuccess() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastSuccess = time.Now()
	h.consecutiveFails = 0
	h.breaker.RecordSuccess()
}

func (h *HealthManager) RecordFailure() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.lastFailure = time.Now()
	h.consecutiveFails++
	h.breaker.RecordFailure()
}

func (h *HealthManager) GetStatus() models.HealthStatus {
	h.mu.RLock()
	defer h.mu.RUnlock()

	status := "healthy"
	if h.consecutiveFails > 0 {
		status = "degraded"
	}
	if h.breaker.GetState() == breaker.StateOpen {
		status = "failing"
	}

	return models.HealthStatus{
		Status:           status,
		LastSuccess:      h.lastSuccess,
		LastFailure:      h.lastFailure,
		ConsecutiveFails: h.consecutiveFails,
		BreakerState:     h.breaker.GetState(),
		Uptime:           time.Since(h.startTime),
	}
}
