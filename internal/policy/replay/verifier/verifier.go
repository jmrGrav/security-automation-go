package verifier

import (
	"context"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/policy/opa"
	"github.com/jm/security-automation-go/internal/policy/replay/evidence"
)

// Verifier re-evaluates past governance decisions.
type Verifier struct {
	opa *opa.Engine
}

func New(oe *opa.Engine) *Verifier {
	return &Verifier{opa: oe}
}

type ReplayResult struct {
	OriginalDecision models.Decision
	ReplayDecision   models.Decision
	Matched          bool
	Reason           string
}

// Verify re-runs the decision based on provided evidence and input.
func (v *Verifier) Verify(ctx context.Context, ev evidence.GovernanceEvidence, input models.PolicyInput) (*ReplayResult, error) {
	const op = "policy.replay.verifier.Verify"

	decision, reason, err := v.opa.Evaluate(ctx, input)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}

	res := &ReplayResult{
		OriginalDecision: ev.FinalDecision,
		ReplayDecision:   decision,
		Matched:          ev.FinalDecision == decision,
		Reason:           reason,
	}

	return res, nil
}
