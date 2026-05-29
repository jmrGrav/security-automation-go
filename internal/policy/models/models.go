package models

import (
	"time"

	"github.com/jm/security-automation-go/internal/runtime/breaker"
)

type Decision string

const (
	DecisionAllow           Decision = "allow"
	DecisionDeny            Decision = "deny"
	DecisionWarn            Decision = "warn"
	DecisionAuditOnly       Decision = "audit_only"
	DecisionQuarantine      Decision = "quarantine"
	DecisionRequireApproval Decision = "require_approval"
	DecisionCooldown        Decision = "cooldown"
)

type RiskLevel string

const (
	RiskLow      RiskLevel = "low"
	RiskMedium   RiskLevel = "medium"
	RiskHigh     RiskLevel = "high"
	RiskCritical RiskLevel = "critical"
)

// Policy represents a named set of governance rules.
type Policy struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	Rules       []Rule `json:"rules" yaml:"rules"`
	Enabled     bool   `json:"enabled" yaml:"enabled"`
}

// Rule defines a single governance constraint.
type Rule struct {
	ID          string   `json:"id" yaml:"id"`
	Description string   `json:"description" yaml:"description"`
	Target      string   `json:"target" yaml:"target"`       // e.g., "mutation_batch", "rollback_batch"
	Condition   string   `json:"condition" yaml:"condition"` // e.g., "mutation_count > 100"
	Decision    Decision `json:"decision" yaml:"decision"`
}

// EvaluationContext carries all signals required for policy decisions.
type EvaluationContext struct {
	Timestamp  time.Time `json:"ts"`
	OperatorID string    `json:"operator_id,omitempty"`
	TargetType string    `json:"target_type"` // "mutation", "rollback", "quarantine", "breaker"

	// Payload details
	MutationCount int      `json:"mutation_count"`
	Drift         float64  `json:"drift"`
	ResourceTypes []string `json:"resource_types"`
	ResourceIDs   []string `json:"resource_ids"`

	// System signals
	BreakerState  breaker.State `json:"breaker_state"`
	InMaintenance bool          `json:"in_maintenance"`

	// IDs for correlation
	TraceID string `json:"trace_id,omitempty"`
	PlanID  string `json:"plan_id,omitempty"`
	BatchID string `json:"batch_id,omitempty"`
}

// AdmissionDecision is the final outcome of a policy evaluation.
type AdmissionDecision struct {
	Allowed    bool              `json:"allowed"`
	Decision   Decision          `json:"decision"`
	Reason     string            `json:"reason"`
	Violations []PolicyViolation `json:"violations,omitempty"`
	TraceID    string            `json:"trace_id"`
}

type PolicyViolation struct {
	PolicyID    string `json:"policy_id"`
	RuleID      string `json:"rule_id"`
	Description string `json:"description"`
}

// ApprovalStatus tracks the lifecycle of a required approval.
type ApprovalStatus string

const (
	ApprovalPending  ApprovalStatus = "pending"
	ApprovalApproved ApprovalStatus = "approved"
	ApprovalRejected ApprovalStatus = "rejected"
	ApprovalExpired  ApprovalStatus = "expired"
)

type ApprovalRecord struct {
	ID          string         `json:"id"`
	RequestedBy string         `json:"requested_by"`
	CreatedAt   time.Time      `json:"created_at"`
	ExpiresAt   time.Time      `json:"expires_at"`
	Status      ApprovalStatus `json:"status"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}
