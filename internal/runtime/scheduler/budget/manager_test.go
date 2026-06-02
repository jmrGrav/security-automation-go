package budget

import (
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

func TestManagerEnforcesTenantConcurrencyBudget(t *testing.T) {
	t.Parallel()

	manager := NewManager()
	manager.RegisterTenant(models.TenantBudget{TenantID: "tenant-a", MaxConcurrentWorkers: 1})

	if !manager.Acquire("tenant-a") {
		t.Fatal("first acquire should succeed")
	}
	if manager.Acquire("tenant-a") {
		t.Fatal("second acquire should be refused while budget is exhausted")
	}

	manager.Release("tenant-a")
	if !manager.Acquire("tenant-a") {
		t.Fatal("acquire should succeed again after release")
	}
}

func TestManagerDefaultsUnknownTenantsToSingleWorker(t *testing.T) {
	t.Parallel()

	manager := NewManager()
	if !manager.Acquire("unknown") {
		t.Fatal("first acquire for unknown tenant should use default budget")
	}
	if manager.Acquire("unknown") {
		t.Fatal("unknown tenant should default to one concurrent worker")
	}
}
