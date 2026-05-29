package models

import (
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/runtime/drift"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/scope"
)

// PolicyInput is the canonical model sent to the OPA engine for decision making.
type PolicyInput struct {
	Scope     scope.RuntimeScope       `json:"scope"`
	Runtime   RuntimeContext           `json:"runtime"`
	Batch     *execution.MutationBatch `json:"batch,omitempty"`
	Drift     *drift.DriftEvent        `json:"drift,omitempty"`
	Governor  GovernorContext          `json:"governor"`
	Lifecycle models.LifecycleState    `json:"lifecycle"`
}

type RuntimeContext struct {
	BreakerState  string `json:"breaker_state"`
	InMaintenance bool   `json:"in_maintenance"`
	IsDryRun      bool   `json:"is_dry_run"`
}

type GovernorContext struct {
	Pressure   float64                 `json:"pressure"`
	ActiveRuns int                     `json:"active_runs"`
	Budgets    []governor.BudgetStatus `json:"budgets,omitempty"`
}
