package resources

import (
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Capability defines what the system can do with a resource.
type Capability string

const (
	CapRead   Capability = "read"
	CapCreate Capability = "create"
	CapUpdate Capability = "update"
	CapDelete Capability = "delete"
)

// Ownership defines who controls the resource lifecycle.
type Ownership string

const (
	OwnershipFullyManaged     Ownership = "fully_managed"     // System has exclusive control
	OwnershipPartiallyManaged Ownership = "partially_managed" // System manages specific fields/items
	OwnershipExternallyOwned  Ownership = "externally_owned"  // System only reads/references
)

// Descriptor defines a Cloudflare resource type and its relationships.
type Descriptor struct {
	Type         snapshot.ResourceType
	Dependencies []snapshot.ResourceType
	Capabilities []Capability
	DefaultOwner Ownership
}

// Registry is the central source of resource metadata.
type Registry struct {
	descriptors map[snapshot.ResourceType]Descriptor
}

func NewRegistry() *Registry {
	r := &Registry{
		descriptors: make(map[snapshot.ResourceType]Descriptor),
	}
	r.init()
	return r
}

func (r *Registry) init() {
	// IP Access Rules: No dependencies
	r.Register(Descriptor{
		Type:         snapshot.ResourceIPAccessRules,
		Capabilities: []Capability{CapRead, CapCreate, CapDelete},
		DefaultOwner: OwnershipFullyManaged,
	})

	// Firewall Lists: No dependencies
	r.Register(Descriptor{
		Type:         snapshot.ResourceLists,
		Capabilities: []Capability{CapRead, CapCreate, CapDelete},
		DefaultOwner: OwnershipFullyManaged,
	})

	// Firewall List Items: Depend on Lists
	r.Register(Descriptor{
		Type:         snapshot.ResourceListItems,
		Dependencies: []snapshot.ResourceType{snapshot.ResourceLists},
		Capabilities: []Capability{CapRead, CapCreate, CapDelete},
		DefaultOwner: OwnershipPartiallyManaged,
	})

	// Rulesets: Generic containers for rules
	r.Register(Descriptor{
		Type:         snapshot.ResourceRulesets,
		Capabilities: []Capability{CapRead, CapUpdate}, // Usually root rulesets are updated, not created
		DefaultOwner: OwnershipPartiallyManaged,
	})

	// Ruleset Rules: Indivual rules within a ruleset
	r.Register(Descriptor{
		Type:         snapshot.ResourceRulesetRules,
		Dependencies: []snapshot.ResourceType{snapshot.ResourceRulesets},
		Capabilities: []Capability{CapRead, CapCreate, CapUpdate, CapDelete},
		DefaultOwner: OwnershipFullyManaged,
	})
}

func (r *Registry) Register(d Descriptor) {
	r.descriptors[d.Type] = d
}

func (r *Registry) Get(rt snapshot.ResourceType) (Descriptor, bool) {
	d, ok := r.descriptors[rt]
	return d, ok
}

func (r *Registry) All() []Descriptor {
	out := make([]Descriptor, 0, len(r.descriptors))
	for _, d := range r.descriptors {
		out = append(out, d)
	}
	return out
}
