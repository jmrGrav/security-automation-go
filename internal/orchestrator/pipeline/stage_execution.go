package pipeline

import (
	"context"

	rolmodels "github.com/jm/security-automation-go/internal/rollback/models"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

func (o *Orchestrator) runExecutionStage(ctx context.Context, rollbackBatch rolmodels.RollbackBatch) error {
	if err := o.rolExecutor.ExecuteRollback(ctx, rollbackBatch); err != nil {
		o.bus.Emit(models.EventRunFailed, rollbackBatch.ID, map[string]interface{}{"error": err.Error()})
		_ = o.sm.Transition(ctx, models.StatusQuarantined, "rollback failed")
		return err
	}
	return nil
}
