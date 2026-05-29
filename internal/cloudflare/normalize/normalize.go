package normalize

import (
	"fmt"

	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Normalizer converts provider-specific resources into normalized snapshot entities.
type Normalizer struct{}

func New() *Normalizer {
	return &Normalizer{}
}

// IPAccessRules converts Cloudflare IP Access Rules into normalized objects.
func (n *Normalizer) IPAccessRules(rules []models.IPAccessRule) []snapshot.NormalizedObject {
	out := make([]snapshot.NormalizedObject, 0, len(rules))
	for _, r := range rules {
		// StableIdentityKey: ip:target:value:mode
		sik := fmt.Sprintf("ip:%s:%s:%s", r.Configuration.Target, r.Configuration.Value, r.Mode)

		out = append(out, snapshot.NormalizedObject{
			ObjectID:          r.ID,
			ObjectType:        string(snapshot.ResourceIPAccessRules),
			StableIdentityKey: sik,
			Attributes: map[string]any{
				"mode":  r.Mode,
				"notes": r.Notes,
				"configuration": map[string]any{
					"target": r.Configuration.Target,
					"value":  r.Configuration.Value,
				},
			},
		})
	}
	return out
}

// FirewallLists converts Cloudflare Firewall Lists into normalized objects.
func (n *Normalizer) FirewallLists(lists []models.FirewallList) []snapshot.NormalizedObject {
	out := make([]snapshot.NormalizedObject, 0, len(lists))
	for _, l := range lists {
		// StableIdentityKey: list:name
		sik := fmt.Sprintf("list:%s", l.Name)

		out = append(out, snapshot.NormalizedObject{
			ObjectID:          l.ID,
			ObjectType:        string(snapshot.ResourceLists),
			StableIdentityKey: sik,
			Attributes: map[string]any{
				"name":        l.Name,
				"description": l.Description,
				"kind":        l.Kind,
			},
		})
	}
	return out
}

// FirewallListItems converts Cloudflare Firewall List Items into normalized objects.
func (n *Normalizer) FirewallListItems(items []models.FirewallListItem) []snapshot.NormalizedObject {
	out := make([]snapshot.NormalizedObject, 0, len(items))
	for _, i := range items {
		// StableIdentityKey: list_item:ip
		sik := fmt.Sprintf("list_item:%s", i.IP)

		out = append(out, snapshot.NormalizedObject{
			ObjectID:          i.ID,
			ObjectType:        string(snapshot.ResourceListItems),
			StableIdentityKey: sik,
			Attributes: map[string]any{
				"ip":      i.IP,
				"comment": i.Comment,
			},
		})
	}
	return out
}
