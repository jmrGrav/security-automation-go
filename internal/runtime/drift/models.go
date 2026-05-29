package drift

import (
	"github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"time"
)

type Class string

const (
	ClassBenign      Class = "benign"
	ClassOperator    Class = "operator"
	ClassHostile     Class = "hostile"
	ClassProvider    Class = "provider"
	ClassOscillation Class = "oscillation"
	ClassStale       Class = "stale"
	ClassOwnership   Class = "ownership"
	ClassConvergence Class = "convergence"
)

type RiskLevel string

const (
	LevelInfo     RiskLevel = "info"
	LevelLow      RiskLevel = "low"
	LevelMedium   RiskLevel = "medium"
	LevelHigh     RiskLevel = "high"
	LevelCritical RiskLevel = "critical"
)

type EscalationAction string

const (
	ActionIgnore          EscalationAction = "ignore"
	ActionAuditOnly       EscalationAction = "audit_only"
	ActionRetry           EscalationAction = "retry"
	ActionCooldown        EscalationAction = "cooldown"
	ActionRequireApproval EscalationAction = "require_approval"
	ActionQuarantine      EscalationAction = "quarantine"
	ActionRollback        EscalationAction = "rollback"
	ActionBreakerOpen     EscalationAction = "breaker_open"
)

// DriftEvent represents a single detected divergence.
type DriftEvent struct {
	ID                string    `json:"drift_id"`
	Timestamp         time.Time `json:"timestamp"`
	StableIdentityKey string    `json:"stable_identity_key"`
	ResourceType      string    `json:"resource_type"`

	// Classification
	Classification Class             `json:"classification"`
	Fingerprint    string            `json:"fingerprint"`
	RiskLevel      RiskLevel         `json:"risk_level"`
	RiskScore      float64           `json:"risk_score"` // 0.0 to 1.0
	Confidence     memory.Confidence `json:"confidence"`

	// Context
	EpochID string `json:"epoch_id"`
	TraceID string `json:"trace_id"`
	PlanID  string `json:"plan_id,omitempty"`

	// Details
	Diff     string         `json:"diff,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// EscalationDecision defines how the system should react to drift.
type EscalationDecision struct {
	Action EscalationAction `json:"action"`
	Reason string           `json:"reason"`
}
