package evidence

import (
	"time"

	polmodels "github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
)

// DecisionRecord captures the outcome of a single rule evaluation.
type DecisionRecord struct {
	PolicyID string             `json:"policy_id"`
	RuleID   string             `json:"rule_id,omitempty"`
	Outcome  polmodels.Decision `json:"outcome"`
	Reason   string             `json:"reason,omitempty"`
}

// GovernanceEvidence is the immutable record of a policy decision.
type GovernanceEvidence struct {
	EvidenceID string    `json:"evidence_id"`
	Timestamp  time.Time `json:"timestamp"`

	// Scope context
	ScopeID  string `json:"scope_id"`
	TenantID string `json:"tenant_id"`

	// Run context
	RunID   string `json:"run_id"`
	PlanID  string `json:"plan_id,omitempty"`
	BatchID string `json:"batch_id,omitempty"`

	// Observability
	TraceID string `json:"trace_id"`
	SpanID  string `json:"span_id,omitempty"`

	// State snapshot at decision time
	RuntimeEpoch    int64  `json:"runtime_epoch"`
	FencingToken    int64  `json:"fencing_token"`
	LifecycleStatus string `json:"lifecycle_status"`

	// Policy bundle details
	PolicyBundleID  string `json:"policy_bundle_id"`
	PolicyBundleSHA string `json:"policy_bundle_sha"`

	// Integrity checks
	InputChecksum    string `json:"input_checksum"`
	SnapshotChecksum string `json:"snapshot_checksum,omitempty"`

	// Decision details
	FinalDecision polmodels.Decision `json:"final_decision"`
	Decisions     []DecisionRecord   `json:"decisions"`

	// Domain context
	OwnershipClaims  []ownership.OwnershipClaim `json:"ownership_claims,omitempty"`
	GovernorPressure float64                    `json:"governor_pressure"`

	// Security
	Signature string `json:"signature,omitempty"`
}
