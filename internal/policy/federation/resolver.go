package federation

import (
	"sort"
	"sync"

	"github.com/jm/security-automation-go/internal/policy/models"
)

// Resolver manages federated policy evaluation and decision merging.
type Resolver struct {
	mu      sync.RWMutex
	bundles map[string]FederatedBundle
}

func NewResolver() *Resolver {
	return &Resolver{
		bundles: make(map[string]FederatedBundle),
	}
}

// RegisterBundle registers a bundle at a specific scope.
func (r *Resolver) RegisterBundle(b FederatedBundle) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.bundles[b.BundleID] = b
}

// MergeDecisions implements the hierarchical "most restrictive wins" logic.
func (r *Resolver) MergeDecisions(decisions []ScopedDecision) FederatedDecision {
	if len(decisions) == 0 {
		return FederatedDecision{
			FinalDecision: models.DecisionAllow,
			Reason:        "no decisions to merge, default allow",
		}
	}

	// Sort decisions by severity priority
	// DENY > QUARANTINE > REQUIRE_APPROVAL > COOLDOWN > WARN > AUDIT_ONLY > ALLOW
	priority := map[models.Decision]int{
		models.DecisionDeny:            100,
		models.DecisionQuarantine:      80,
		models.DecisionRequireApproval: 60,
		models.DecisionCooldown:        40,
		models.DecisionWarn:            20,
		models.DecisionAuditOnly:       10,
		models.DecisionAllow:           0,
	}

	sort.Slice(decisions, func(i, j int) bool {
		return priority[decisions[i].Decision] > priority[decisions[j].Decision]
	})

	res := FederatedDecision{
		FinalDecision: decisions[0].Decision,
		Reason:        decisions[0].Reason,
		Contributors:  decisions,
	}

	return res
}

// ResolveScopeHierarchy determines the active bundles for a given context.
func (r *Resolver) ResolveScopeHierarchy(tenantID, zoneID string) []FederatedBundle {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var active []FederatedBundle
	for _, b := range r.bundles {
		// Matches global or specific tenant/zone
		if b.Scope == ScopeGlobal ||
			(b.Scope == ScopeTenant && b.ScopeID == tenantID) ||
			(b.Scope == ScopeZone && b.ScopeID == zoneID) {
			active = append(active, b)
		}
	}

	// Sort by priority (higher first)
	sort.Slice(active, func(i, j int) bool {
		return active[i].Priority > active[j].Priority
	})

	return active
}
