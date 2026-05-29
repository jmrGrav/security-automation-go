package adapter

import (
	"context"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// Executor defines the contract for applying CrowdSec actions.
type Executor interface {
	Execute(ctx context.Context, batch models.Batch) (models.BatchResult, error)
}
