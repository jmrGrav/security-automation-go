package recovery

import (
	"fmt"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

// Strategy defines how to handle an incomplete previous run.
type Strategy string

const (
	StrategyResume     Strategy = "resume"
	StrategyQuarantine Strategy = "quarantine"
	StrategyIgnore     Strategy = "ignore"
)

func DetermineStrategy(lastState models.RuntimeState) (Strategy, string) {
	if lastState.ActiveRollbackID != "" {
		return StrategyResume, fmt.Sprintf("previous rollback %s was interrupted", lastState.ActiveRollbackID)
	}
	if lastState.IncompleteBatchID != "" {
		return StrategyQuarantine, fmt.Sprintf("previous batch %s was left in incomplete state", lastState.IncompleteBatchID)
	}
	return StrategyResume, ""
}
