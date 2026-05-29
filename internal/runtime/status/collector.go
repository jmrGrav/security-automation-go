package status

import (
	"os"
	"path/filepath"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/health"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

// Collector aggregates runtime signals into a unified status report.
type Collector struct {
	version       string
	startTime     time.Time
	health        *health.HealthManager
	breaker       *breaker.CircuitBreaker
	stateStore    *state.StateStore
	lockPath      string
	quarantineDir string
}

func NewCollector(version string, startTime time.Time, h *health.HealthManager, cb *breaker.CircuitBreaker, ss *state.StateStore, lockPath, qDir string) *Collector {
	return &Collector{
		version:       version,
		startTime:     startTime,
		health:        h,
		breaker:       cb,
		stateStore:    ss,
		lockPath:      lockPath,
		quarantineDir: qDir,
	}
}

func (c *Collector) Collect() (RuntimeStatus, error) {
	hStatus := c.health.GetStatus()
	runtimeState, _ := c.stateStore.Load()

	status := RuntimeStatus{
		Version:   c.version,
		StartedAt: c.startTime,
		Uptime:    time.Since(c.startTime).Round(time.Second).String(),
		Health: HealthStatus{
			Status:           hStatus.Status,
			ConsecutiveFails: hStatus.ConsecutiveFails,
			LastSuccess:      formatTime(hStatus.LastSuccess),
			LastFailure:      formatTime(hStatus.LastFailure),
		},
		Breaker: BreakerStatus{
			State: MapBreakerState(c.breaker.GetState()),
			// Note: FailureCount is internal to breaker, we might want to expose it if needed
		},
		Lock: LockStatus{
			IsLocked: c.isLocked(),
		},
		Reconciliation: ReconciliationStatus{
			LastSuccessAt:       formatTime(runtimeState.LastSuccessAt),
			LastAppliedSnapshot: runtimeState.LastAppliedSnapshot,
			LastPlanID:          runtimeState.LastPlanID,
			// DriftDetected is complex to determine from just state, maybe metadata in State?
		},
		Quarantine: QuarantineStatus{
			ActiveItems: c.countQuarantine(),
		},
	}

	return status, nil
}

func (c *Collector) isLocked() bool {
	// Simple check: if we can't acquire the lock, it's probably locked.
	// But the collector is read-only. We can check if the file exists and has content.
	if _, err := os.Stat(c.lockPath); err != nil {
		return false
	}
	return true
}

func (c *Collector) countQuarantine() int {
	files, err := os.ReadDir(c.quarantineDir)
	if err != nil {
		return 0
	}
	count := 0
	for _, f := range files {
		if !f.IsDir() && filepath.Ext(f.Name()) == ".json" {
			count++
		}
	}
	return count
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}
