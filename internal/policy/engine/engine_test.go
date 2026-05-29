package engine

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
)

func TestEngine_Evaluate(t *testing.T) {
	policies := []models.Policy{
		{
			ID:      "p1",
			Enabled: true,
			Rules: []models.Rule{
				{
					ID:        "deny-on-breaker-open",
					Target:    "mutation",
					Decision:  models.DecisionDeny,
					Condition: "breaker == open",
				},
				{
					ID:        "require-approval-on-large-mutation",
					Target:    "mutation",
					Decision:  models.DecisionRequireApproval,
					Condition: "mutation_count > 100",
				},
			},
		},
	}

	eng := New(policies)
	ctx := context.Background()

	// 1. Happy path
	evalCtx := models.EvaluationContext{
		TargetType:    "mutation",
		MutationCount: 10,
		BreakerState:  breaker.StateClosed,
	}
	res := eng.Evaluate(ctx, evalCtx)
	if !res.Allowed || res.Decision != models.DecisionAllow {
		t.Errorf("expected allow, got %s", res.Decision)
	}

	// 2. Deny on breaker open
	evalCtx.BreakerState = breaker.StateOpen
	res = eng.Evaluate(ctx, evalCtx)
	if res.Allowed || res.Decision != models.DecisionDeny {
		t.Errorf("expected deny on breaker open, got %s", res.Decision)
	}

	// 3. Require approval
	evalCtx.BreakerState = breaker.StateClosed
	evalCtx.MutationCount = 150
	res = eng.Evaluate(ctx, evalCtx)
	if !res.Allowed || res.Decision != models.DecisionRequireApproval {
		t.Errorf("expected require_approval, got %s", res.Decision)
	}
}
