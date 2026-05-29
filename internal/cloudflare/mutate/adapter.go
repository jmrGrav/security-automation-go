package mutate

import (
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// RegisterAll registers all Cloudflare-specific mutators into the governed executor.
func RegisterAll(e *execution.GovernedExecutor, t *transport.Transport, zoneID, accountID string) {
	e.RegisterMutator(string(snapshot.ResourceIPAccessRules), NewIPAccessRuleMutator(t, zoneID))
	e.RegisterMutator(string(snapshot.ResourceLists), NewFirewallListMutator(t, accountID))
	e.RegisterMutator(string(snapshot.ResourceListItems), NewFirewallListItemMutator(t, accountID))
	e.RegisterMutator(string(snapshot.ResourceRulesets), NewRulesetMutator(t, zoneID))
	e.RegisterMutator(string(snapshot.ResourceRulesetRules), NewRulesetMutator(t, zoneID))
}
