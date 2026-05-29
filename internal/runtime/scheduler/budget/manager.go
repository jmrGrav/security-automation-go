package budget

import (
	"sync"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

// Manager tracks and enforces operational budgets across tenants.
type Manager struct {
	mu      sync.RWMutex
	budgets map[string]models.TenantBudget
	active  map[string]int // tenantID -> current worker count
}

func NewManager() *Manager {
	return &Manager{
		budgets: make(map[string]models.TenantBudget),
		active:  make(map[string]int),
	}
}

func (m *Manager) RegisterTenant(b models.TenantBudget) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.budgets[b.TenantID] = b
}

// Acquire slot for a worker if budget allows.
func (m *Manager) Acquire(tenantID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	b, ok := m.budgets[tenantID]
	if !ok {
		// Default budget for unknown tenants
		b = models.TenantBudget{MaxConcurrentWorkers: 1}
	}

	if m.active[tenantID] >= b.MaxConcurrentWorkers {
		return false
	}

	m.active[tenantID]++
	return true
}

func (m *Manager) Release(tenantID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.active[tenantID]--
}

func (m *Manager) GetBudget(tenantID string) models.TenantBudget {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if b, ok := m.budgets[tenantID]; ok {
		return b
	}
	return models.TenantBudget{TenantID: tenantID, MaxConcurrentWorkers: 1}
}

func (m *Manager) GetActiveCounts() map[string]int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]int)
	for k, v := range m.active {
		out[k] = v
	}
	return out
}
