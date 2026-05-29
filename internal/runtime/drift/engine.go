package drift

import (
	"context"
	"log/slog"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"github.com/jm/security-automation-go/internal/runtime/engine"
)

// Engine is the high-level drift intelligence service.
type Engine struct {
	classifier *Classifier
	scorer     *Scorer
	escalator  *EscalationEngine
	memStore   *memory.Store
	logger     *slog.Logger
}

func NewEngine(r *resources.Registry, sm *engine.StateMachine, ms *memory.Store, logger *slog.Logger) *Engine {
	return &Engine{
		classifier: NewClassifier(r),
		scorer:     NewScorer(),
		escalator:  NewEscalationEngine(sm, logger),
		memStore:   ms,
		logger:     logger,
	}
}

func (e *Engine) Process(ctx context.Context, event *DriftEvent, scopeID, leaderID string) EscalationDecision {
	e.classifier.Classify(event)
	e.scorer.Score(event)

	// Temporal Memory Update
	hist := e.memStore.Record(event.Fingerprint, event.RiskScore, scopeID, leaderID)
	if hist.Occurrences > 5 && event.Classification == ClassConvergence {
		event.Classification = ClassOscillation
		e.scorer.Score(event) // Re-score
	}

	decision := e.escalator.Decide(ctx, *event)

	e.logger.Info("drift_processed",
		"drift_id", event.ID,
		"classification", event.Classification,
		"risk_level", event.RiskLevel,
		"risk_score", event.RiskScore,
		"action", decision.Action,
	)

	return decision
}
