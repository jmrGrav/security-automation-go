package pipeline

import (
	"context"

	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

func (o *Orchestrator) runValidationStage(ctx context.Context, actions []csmodels.ExecutableOperation) error {
	if err := o.csValidator.Validate(actions); err != nil {
		metrics.ReconciliationFailuresTotal.Inc()
		o.health.RecordFailure()
		_ = o.sm.Transition(ctx, models.StatusFailed, "validation failed")
		return err
	}
	return nil
}
