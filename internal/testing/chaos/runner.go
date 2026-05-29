package chaos

import (
	"context"
	"fmt"
	"time"

	"github.com/jm/security-automation-go/internal/orchestrator/pipeline"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// Runner executes chaos scenarios against the orchestrator.
type Runner struct {
	orch *pipeline.Orchestrator
}

func NewRunner(orch *pipeline.Orchestrator) *Runner {
	return &Runner{orch: orch}
}

func (r *Runner) RunScenario(ctx context.Context, s Scenario) (Result, error) {
	const op = "testing.chaos.Runner.RunScenario"

	result := Result{
		ScenarioID: s.ID,
		StartTime:  time.Now().UTC(),
		Passed:     true,
	}

	// 1. Setup Injections (This would involve configuring the ReplayEngine or Mocks)
	// For now, we assume the orchestrator's dependencies are already "wired" for chaos
	// OR we inject them here via specialized decorators.

	// 2. Execute full pipeline run
	prov := snapshot.ProvenanceMetadata{
		GeneratedBy: "chaos-runner",
		ReplayID:    s.ID,
	}

	// We use the DryRun pipeline as the primary chaos target for now
	pipeRes, err := r.orch.DryRun(ctx, "chaos-zone", snapshot.ResourceIPAccessRules, prov)

	// 3. Collect assertions
	r.checkExpectations(s, pipeRes, err, &result)

	result.Duration = time.Since(result.StartTime)
	return result, nil
}

func (r *Runner) checkExpectations(s Scenario, pipeRes interface{}, pipeErr error, result *Result) {
	// Logic to verify breaker state, quarantine count, etc.
	// This would query healthMgr, quarantine store, etc. from the orchestrator.

	if s.Expectations.Success != nil {
		success := pipeErr == nil
		if success != *s.Expectations.Success {
			result.Passed = false
			result.Failures = append(result.Failures, fmt.Sprintf("expected success=%v, got %v (err: %v)", *s.Expectations.Success, success, pipeErr))
		}
	}

	// TODO: Add more detailed checks for Breaker, Quarantine, etc.
}
