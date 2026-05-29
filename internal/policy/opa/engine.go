package opa

import (
	"context"
	"log/slog"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/policy/models"
	"github.com/open-policy-agent/opa/rego"
)

// Engine is the OPA-backed policy evaluation service.
type Engine struct {
	query  rego.PreparedEvalQuery
	logger *slog.Logger
}

func NewEngine(ctx context.Context, logger *slog.Logger, regoCode string) (*Engine, error) {
	const op = "policy.opa.NewEngine"

	r := rego.New(
		rego.Query("data.cfsync.admission.decision"),
		rego.Module("admission.rego", regoCode),
	)

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}

	return &Engine{
		query:  query,
		logger: logger,
	}, nil
}

// Evaluate runs the input through the Rego policy and returns a decision.
func (e *Engine) Evaluate(ctx context.Context, input models.PolicyInput) (models.Decision, string, error) {
	const op = "policy.opa.Evaluate"

	results, err := e.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return models.DecisionDeny, "eval_error", apperr.Wrap(op, err)
	}

	if len(results) == 0 {
		return models.DecisionAllow, "default_allow", nil
	}

	// Assuming the result is a string (models.Decision)
	decision, ok := results[0].Expressions[0].Value.(string)
	if !ok {
		return models.DecisionDeny, "malformed_decision", nil
	}

	return models.Decision(decision), "policy_match", nil
}
