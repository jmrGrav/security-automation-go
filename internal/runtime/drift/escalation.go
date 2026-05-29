package drift

import (
	"context"
	"log/slog"

	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

// EscalationEngine determines the system's reaction to drift.
type EscalationEngine struct {
	sm     *engine.StateMachine
	logger *slog.Logger
}

func NewEscalationEngine(sm *engine.StateMachine, logger *slog.Logger) *EscalationEngine {
	return &EscalationEngine{
		sm:     sm,
		logger: logger,
	}
}

func (e *EscalationEngine) Decide(ctx context.Context, event DriftEvent) EscalationDecision {
	switch event.Classification {
	case ClassHostile:
		// Hostile drift triggers immediate quarantine and failure
		_ = e.sm.Transition(ctx, models.StatusQuarantined, "hostile drift detected")
		return EscalationDecision{Action: ActionQuarantine, Reason: "hostile drift detected"}

	case ClassOwnership:
		return EscalationDecision{Action: ActionRequireApproval, Reason: "ownership violation"}

	case ClassOscillation:
		return EscalationDecision{Action: ActionCooldown, Reason: "reconciliation oscillation detected"}

	case ClassConvergence:
		return EscalationDecision{Action: ActionRetry, Reason: "transient convergence failure"}

	case ClassBenign:
		return EscalationDecision{Action: ActionAuditOnly, Reason: "benign drift"}

	default:
		return EscalationDecision{Action: ActionAuditOnly, Reason: "manual operator drift"}
	}
}
