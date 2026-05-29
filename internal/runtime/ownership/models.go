package ownership

import (
	"time"
)

type DomainType string

const (
	DomainTerraform         DomainType = "terraform"
	DomainCFSync            DomainType = "cf-sync"
	DomainDashboard         DomainType = "dashboard"
	DomainCloudflareManaged DomainType = "cloudflare_managed"
)

type TrustLevel int

const (
	TrustImmutable     TrustLevel = 255
	TrustAuthoritative TrustLevel = 100
	TrustManaged       TrustLevel = 80
	TrustOpportunistic TrustLevel = 40
	TrustUnknown       TrustLevel = 0
)

type Right string

const (
	RightCreate   Right = "create"
	RightUpdate   Right = "update"
	RightDelete   Right = "delete"
	RightRollback Right = "rollback"
	RightOverride Right = "override"
)

// OwnershipDomain defines a source of truth/mutator.
type OwnershipDomain struct {
	ID           string     `json:"id"`
	Type         DomainType `json:"type"`
	Priority     int        `json:"priority"`
	Trust        TrustLevel `json:"trust_level"`
	Capabilities []Right    `json:"capabilities"`
}

// OwnershipClaim represents a current sovereignty over a resource.
type OwnershipClaim struct {
	ScopeID    string    `json:"scope_id"`
	ResourceID string    `json:"resource_id"` // SIK or internal ID
	DomainID   string    `json:"domain_id"`
	Epoch      int64     `json:"epoch"`
	Rights     []Right   `json:"rights"`
	Timestamp  time.Time `json:"timestamp"`
}

// ResolutionOutcome defines the result of an ownership check.
type ResolutionOutcome struct {
	Allowed bool   `json:"allowed"`
	Action  string `json:"action"` // allow, deny, require_approval, readonly
	Reason  string `json:"reason"`
	Owner   string `json:"current_owner"`
}

type LineageEventType string

const (
	LineageEventResolve LineageEventType = "resolve"
	LineageEventClaim   LineageEventType = "claim"
)

type LineageEvent struct {
	ID            string           `json:"id"`
	ParentID      string           `json:"parent_id,omitempty"`
	ScopeID       string           `json:"scope_id"`
	ResourceID    string           `json:"resource_id"`
	DomainID      string           `json:"domain_id"`
	EventType     LineageEventType `json:"event_type"`
	Decision      string           `json:"decision,omitempty"`
	RequiredRight Right            `json:"required_right,omitempty"`
	OwnerDomain   string           `json:"owner_domain,omitempty"`
	Epoch         int64            `json:"epoch,omitempty"`
	FencingToken  int64            `json:"fencing_token,omitempty"`
	Reason        string           `json:"reason,omitempty"`
	DecisionHash  string           `json:"decision_hash"`
	CreatedAt     time.Time        `json:"created_at"`
}
