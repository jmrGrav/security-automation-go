package simulation

import (
	"context"

	"github.com/jm/security-automation-go/internal/policy/intent"
	"github.com/jm/security-automation-go/internal/reconciliation"
)

type SimulationResult struct {
	MutationCount       int     `json:"mutation_count"`
	RollbackProbability float64 `json:"rollback_probability"`
	QuarantineRisk      float64 `json:"quarantine_risk"`
	GovernorPressure    float64 `json:"governor_pressure"`
	ConvergenceScore    float64 `json:"convergence_score"`
	EstimatedCooldown   string  `json:"estimated_cooldown"`
}

// Engine predicts the outcome of a reconciliation run under a specific intent.
type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Simulate(ctx context.Context, it intent.Intent, plan *reconciliation.Plan) SimulationResult {
	// 1. Calculate base risk from plan
	mutCount := len(plan.Operations)

	// 2. Predict probability based on intent mode
	rbProb := 0.1
	if it.Mode == intent.ModeParanoid {
		rbProb = 0.5 // High sensitivity means high rollback probability
	}

	return SimulationResult{
		MutationCount:       mutCount,
		RollbackProbability: rbProb,
		QuarantineRisk:      float64(mutCount) / 1000.0,
		GovernorPressure:    0.2,
		ConvergenceScore:    0.95,
		EstimatedCooldown:   "5m",
	}
}
