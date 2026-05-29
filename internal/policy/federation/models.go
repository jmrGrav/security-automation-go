package federation

import (
	"time"

	"github.com/jm/security-automation-go/internal/policy/bundles/manifest"
	"github.com/jm/security-automation-go/internal/policy/models"
)

type PolicyScope string

const (
	ScopeGlobal  PolicyScope = "global"
	ScopeTenant  PolicyScope = "tenant"
	ScopeZone    PolicyScope = "zone"
	ScopeRuntime PolicyScope = "runtime"
)

// FederatedBundle is a policy bundle assigned to a specific scope.
type FederatedBundle struct {
	BundleID       string                  `json:"bundle_id"`
	Scope          PolicyScope             `json:"scope"`
	ScopeID        string                  `json:"scope_id,omitempty"` // e.g., tenant ID or zone ID
	ParentBundleID string                  `json:"parent_bundle_id,omitempty"`
	Priority       int                     `json:"priority"`
	Manifest       manifest.BundleManifest `json:"manifest"`
	ActivatedAt    time.Time               `json:"activated_at"`
}

// ScopedDecision carries the decision from a specific policy layer.
type ScopedDecision struct {
	Scope    PolicyScope     `json:"scope"`
	ScopeID  string          `json:"scope_id,omitempty"`
	BundleID string          `json:"bundle_id"`
	Decision models.Decision `json:"decision"`
	Reason   string          `json:"reason,omitempty"`
	RuleID   string          `json:"rule_id,omitempty"`
}

// FederatedDecision is the result of merging multiple scoped decisions.
type FederatedDecision struct {
	FinalDecision models.Decision  `json:"final_decision"`
	Contributors  []ScopedDecision `json:"contributors"`
	Reason        string           `json:"reason"`
	TraceID       string           `json:"trace_id"`
}
