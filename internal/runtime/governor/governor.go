package governor

import (
	"log/slog"
	"sync"

	"github.com/jm/security-automation-go/internal/runtime/limiter"
	"github.com/jm/security-automation-go/internal/runtime/scope"
)

// ResourceGovernor manages hierarchical budgets for external providers.
type ResourceGovernor struct {
	mu            sync.RWMutex
	globalBuckets map[string]map[ResourceType]*limiter.Bucket // provider -> type -> bucket
	tenantBuckets map[string]map[ResourceType]*limiter.Bucket // tenant -> type -> bucket
	scopeBuckets  map[string]map[ResourceType]*limiter.Bucket // scopeID -> type -> bucket

	logger *slog.Logger
}

func New(logger *slog.Logger) *ResourceGovernor {
	return &ResourceGovernor{
		globalBuckets: make(map[string]map[ResourceType]*limiter.Bucket),
		tenantBuckets: make(map[string]map[ResourceType]*limiter.Bucket),
		scopeBuckets:  make(map[string]map[ResourceType]*limiter.Bucket),
		logger:        logger,
	}
}

// RegisterProvider sets global limits for a provider.
func (g *ResourceGovernor) RegisterProvider(name string, limits map[ResourceType]Limit) {
	g.mu.Lock()
	defer g.mu.Unlock()

	buckets := make(map[ResourceType]*limiter.Bucket)
	for rt, l := range limits {
		buckets[rt] = limiter.NewBucket(l.MaxBurst, l.Rate, l.Interval)
	}
	g.globalBuckets[name] = buckets
}

// Allow checks if the given scope is authorized to consume provider resources.
func (g *ResourceGovernor) Allow(s scope.RuntimeScope, provider string, resource ResourceType, n int) bool {
	g.mu.RLock()
	defer g.mu.RUnlock()

	h := &limiter.HierarchicalLimiter{
		Global: g.getGlobalBucket(provider, resource),
		Tenant: g.getTenantBucket(s.Tenant, resource),
		Scope:  g.getScopeBucket(s.ID(), resource),
	}

	return h.Allow(n)
}

func (g *ResourceGovernor) getGlobalBucket(p string, r ResourceType) *limiter.Bucket {
	if prov, ok := g.globalBuckets[p]; ok {
		return prov[r]
	}
	return nil
}

func (g *ResourceGovernor) getTenantBucket(t string, r ResourceType) *limiter.Bucket {
	if ten, ok := g.tenantBuckets[t]; ok {
		return ten[r]
	}
	return nil
}

func (g *ResourceGovernor) getScopeBucket(sid string, r ResourceType) *limiter.Bucket {
	if scp, ok := g.scopeBuckets[sid]; ok {
		return scp[r]
	}
	return nil
}

// Pressure returns a systemic saturation score (0.0 to 1.0).
func (g *ResourceGovernor) Pressure(provider string) float64 {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var max float64
	if prov, ok := g.globalBuckets[provider]; ok {
		for _, b := range prov {
			if s := b.Saturation(); s > max {
				max = s
			}
		}
	}
	return max
}

type BudgetStatus struct {
	Provider   string  `json:"provider"`
	Resource   string  `json:"resource"`
	Saturation float64 `json:"saturation"`
}

func (g *ResourceGovernor) GetAllBudgetsStatus() []BudgetStatus {
	g.mu.RLock()
	defer g.mu.RUnlock()

	var out []BudgetStatus
	for p, types := range g.globalBuckets {
		for rt, b := range types {
			out = append(out, BudgetStatus{
				Provider:   p,
				Resource:   string(rt),
				Saturation: b.Saturation(),
			})
		}
	}
	return out
}
