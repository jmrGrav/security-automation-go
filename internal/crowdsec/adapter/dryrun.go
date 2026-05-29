package adapter

import (
	"context"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// DryRunExecutor only logs the actions without performing any shell commands.
type DryRunExecutor struct{}

func NewDryRunExecutor() *DryRunExecutor {
	return &DryRunExecutor{}
}

func (e *DryRunExecutor) Execute(ctx context.Context, batch models.Batch) (models.BatchResult, error) {
	result := models.BatchResult{
		BatchID:   batch.ID,
		StartTime: time.Now().UTC(),
		Success:   true,
	}

	for _, action := range batch.Actions {
		result.Results = append(result.Results, models.ExecutionResult{
			OperationID: action.OriginatingOpID,
			Status:      "success", // Dry-run always "succeeds" in planning
			Audit: models.AuditTrail{
				Action:     action.Type,
				Target:     action.Value,
				RawCommand: "(dry-run)",
				ExecutedAt: time.Now().UTC(),
				ExecutedBy: "dry-run-executor",
			},
		})
	}

	result.EndTime = time.Now().UTC()
	return result, nil
}
