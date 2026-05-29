package status

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/health"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

func TestCollector_Collect(t *testing.T) {
	dir := t.TempDir()
	cb := breaker.New(5, time.Minute, time.Minute)
	h := health.New(cb)
	ss := state.NewStateStore(dir)

	collector := NewCollector("v1", time.Now(), h, cb, ss, dir+"/lock", dir+"/quarantine")

	res, err := collector.Collect()
	if err != nil {
		t.Fatalf("failed to collect status: %v", err)
	}

	if res.Version != "v1" {
		t.Errorf("expected version v1, got %s", res.Version)
	}
	if res.Health.Status != "healthy" {
		t.Errorf("expected health healthy, got %s", res.Health.Status)
	}
}
