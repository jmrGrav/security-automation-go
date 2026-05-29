package intent

import (
	"time"

	"github.com/jm/security-automation-go/internal/policy/models"
)

type GovernanceMode string

const (
	ModeParanoid          GovernanceMode = "paranoid"
	ModeAvailabilityFirst GovernanceMode = "availability-first"
	ModeTerraformFriendly GovernanceMode = "terraform-friendly"
	ModeForensicLockdown  GovernanceMode = "forensic-lockdown"
)

// Intent represents a high-level business objective for the control-plane.
type Intent struct {
	ID          string         `json:"id" yaml:"id"`
	Mode        GovernanceMode `json:"mode" yaml:"mode"`
	Description string         `json:"description" yaml:"description"`

	// Custom objectives
	MaxRisk     models.RiskLevel `json:"max_risk" yaml:"max_risk"`
	Preferences []string         `json:"preferences" yaml:"preferences"` // e.g., "stability", "low_churn"
}

// Constraints are the technical parameters derived from an Intent.
type Constraints struct {
	RollbackAggressiveness float64       `json:"rollback_aggressiveness"` // 0.0 to 1.0
	MutationBudget         int           `json:"mutation_budget"`
	DestructiveBudget      int           `json:"destructive_budget"`
	DriftTolerance         float64       `json:"drift_tolerance"`
	RetryBackoffMultiplier float64       `json:"retry_backoff_multiplier"`
	QuarantineThreshold    float64       `json:"quarantine_threshold"`
	RequireApproval        bool          `json:"require_approval"`
	CooldownDuration       time.Duration `json:"cooldown_duration"`
}
