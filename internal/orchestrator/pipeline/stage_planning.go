package pipeline

import (
	"time"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/snapshot"
)

func (o *Orchestrator) runPlanningStage(snap *snapshot.Snapshot) (*reconciliation.Plan, error) {
	start := time.Now()
	plan, err := o.planner.Plan(snap, []snapshot.NormalizedObject{})
	metrics.PlanningDurationSeconds.Observe(time.Since(start).Seconds())
	if err != nil {
		return nil, err
	}
	return plan, nil
}
