package normalize

import (
	"fmt"

	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Rulesets converts Cloudflare Rulesets into normalized objects.
func (n *Normalizer) Rulesets(rulesets []models.Ruleset) []snapshot.NormalizedObject {
	out := make([]snapshot.NormalizedObject, 0, len(rulesets))
	for _, rs := range rulesets {
		// StableIdentityKey: ruleset:phase:name
		sik := fmt.Sprintf("ruleset:%s:%s", rs.Phase, rs.Name)

		out = append(out, snapshot.NormalizedObject{
			ObjectID:          rs.ID,
			ObjectType:        string(snapshot.ResourceRulesets),
			StableIdentityKey: sik,
			Attributes: map[string]any{
				"name":        rs.Name,
				"description": rs.Description,
				"kind":        rs.Kind,
				"phase":       rs.Phase,
			},
		})
	}
	return out
}

// RulesetRules converts individual rules from a ruleset into normalized objects.
func (n *Normalizer) RulesetRules(rulesetID string, rules []models.RulesetRule) []snapshot.NormalizedObject {
	out := make([]snapshot.NormalizedObject, 0, len(rules))
	for i, r := range rules {
		// StableIdentityKey: rule:rulesetID:expression:action
		// Note: we include expression/action because Ruleset IDs can be transient or managed
		sik := fmt.Sprintf("rule:%s:%d:%s", rulesetID, i, r.Action)
		if r.Ref != "" {
			sik = fmt.Sprintf("rule:%s:%s", rulesetID, r.Ref)
		}

		out = append(out, snapshot.NormalizedObject{
			ObjectID:          r.ID,
			ObjectType:        string(snapshot.ResourceRulesetRules),
			StableIdentityKey: sik,
			Attributes: map[string]any{
				"action":            r.Action,
				"expression":        r.Expression,
				"description":       r.Description,
				"enabled":           r.Enabled,
				"action_parameters": r.ActionParameters,
				"ref":               r.Ref,
			},
		})
	}
	return out
}
