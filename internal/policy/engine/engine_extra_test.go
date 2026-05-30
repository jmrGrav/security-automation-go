package engine

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
)

// TestEngine_NoPolicies verifies the engine allows all operations when no policies exist.
func TestEngine_NoPolicies(t *testing.T) {
	eng := New(nil)
	res := eng.Evaluate(context.Background(), models.EvaluationContext{TargetType: "mutation"})
	if !res.Allowed {
		t.Error("no policies → must allow")
	}
	if res.Decision != models.DecisionAllow {
		t.Errorf("no policies → must be DecisionAllow, got %q", res.Decision)
	}
	if len(res.Violations) != 0 {
		t.Errorf("no policies → no violations, got %d", len(res.Violations))
	}
}

// TestEngine_DisabledPolicyIgnored verifies disabled policies have no effect.
func TestEngine_DisabledPolicyIgnored(t *testing.T) {
	policies := []models.Policy{
		{
			ID:      "disabled-deny",
			Enabled: false,
			Rules: []models.Rule{
				{ID: "deny-all", Target: "mutation", Decision: models.DecisionDeny, Condition: "breaker == open"},
			},
		},
	}
	eng := New(policies)
	res := eng.Evaluate(context.Background(), models.EvaluationContext{
		TargetType:   "mutation",
		BreakerState: breaker.StateOpen,
	})
	if !res.Allowed {
		t.Error("disabled policy must not affect decision")
	}
}

// TestEngine_MostRestrictiveWins verifies the deny > require_approval > allow priority.
// Uses the engine's predefined rule IDs (matched by switch in engine.matches()).
func TestEngine_MostRestrictiveWins(t *testing.T) {
	policies := []models.Policy{
		{
			ID:      "multi-rule",
			Enabled: true,
			Rules: []models.Rule{
				// require-approval-on-large-mutation fires when MutationCount > 100
				{ID: "require-approval-on-large-mutation", Target: "mutation", Decision: models.DecisionRequireApproval, Condition: "mutation_count > 100"},
				// deny-on-breaker-open fires when BreakerState == open
				{ID: "deny-on-breaker-open", Target: "mutation", Decision: models.DecisionDeny, Condition: "breaker == open"},
			},
		},
	}
	eng := New(policies)

	// Both rules trigger — deny wins (most restrictive)
	res := eng.Evaluate(context.Background(), models.EvaluationContext{
		TargetType:    "mutation",
		MutationCount: 150,
		BreakerState:  breaker.StateOpen,
	})
	if res.Decision != models.DecisionDeny {
		t.Errorf("most restrictive wins: want Deny, got %q", res.Decision)
	}
	if res.Allowed {
		t.Error("Deny must set Allowed=false")
	}
}

// TestEngine_TargetTypeFiltering verifies rules only apply to matching target types.
func TestEngine_TargetTypeFiltering(t *testing.T) {
	policies := []models.Policy{
		{
			ID:      "rollback-deny",
			Enabled: true,
			Rules: []models.Rule{
				{ID: "deny-rb", Target: "rollback_batch", Decision: models.DecisionDeny, Condition: "breaker == open"},
			},
		},
	}
	eng := New(policies)

	// Target is "mutation" — the rollback rule should not apply
	res := eng.Evaluate(context.Background(), models.EvaluationContext{
		TargetType:   "mutation",
		BreakerState: breaker.StateOpen,
	})
	if !res.Allowed {
		t.Error("rule targeting 'rollback_batch' must not apply to 'mutation'")
	}
}

// TestEngine_WildcardTarget verifies rules with "*" target match any type.
// Uses the predefined "deny-on-breaker-open" rule ID.
func TestEngine_WildcardTarget(t *testing.T) {
	policies := []models.Policy{
		{
			ID:      "deny-all-types",
			Enabled: true,
			Rules: []models.Rule{
				{ID: "deny-on-breaker-open", Target: "*", Decision: models.DecisionDeny, Condition: "breaker == open"},
			},
		},
	}
	eng := New(policies)

	for _, target := range []string{"mutation", "rollback_batch", "quarantine", "anything"} {
		res := eng.Evaluate(context.Background(), models.EvaluationContext{
			TargetType:   target,
			BreakerState: breaker.StateOpen,
		})
		if res.Decision != models.DecisionDeny {
			t.Errorf("wildcard target should deny %q, got %q", target, res.Decision)
		}
	}
}

// TestEngine_ViolationsAccumulate verifies all matching violations are recorded.
func TestEngine_ViolationsAccumulate(t *testing.T) {
	policies := []models.Policy{
		{
			ID:      "multi-violation",
			Enabled: true,
			Rules: []models.Rule{
				{ID: "v1", Target: "mutation", Decision: models.DecisionWarn, Condition: "mutation_count > 100"},
				{ID: "v2", Target: "mutation", Decision: models.DecisionWarn, Condition: "mutation_count > 100"},
			},
		},
	}
	eng := New(policies)
	res := eng.Evaluate(context.Background(), models.EvaluationContext{
		TargetType:    "mutation",
		MutationCount: 150,
		BreakerState:  breaker.StateClosed,
	})
	if len(res.Violations) < 2 {
		t.Errorf("want at least 2 violations, got %d", len(res.Violations))
	}
}

// TestEngine_QuarantineOnHighDrift verifies the quarantine rule fires on drift > 0.5.
func TestEngine_QuarantineOnHighDrift(t *testing.T) {
	policies := []models.Policy{
		{
			ID:      "drift-quarantine",
			Enabled: true,
			Rules: []models.Rule{
				{ID: "quarantine-on-high-drift", Target: "mutation", Decision: models.DecisionQuarantine, Condition: "drift > 0.5"},
			},
		},
	}
	eng := New(policies)

	// Low drift → allow
	res := eng.Evaluate(context.Background(), models.EvaluationContext{TargetType: "mutation", Drift: 0.3, BreakerState: breaker.StateClosed})
	if res.Decision != models.DecisionAllow {
		t.Errorf("low drift: want Allow, got %q", res.Decision)
	}

	// High drift → quarantine
	res = eng.Evaluate(context.Background(), models.EvaluationContext{TargetType: "mutation", Drift: 0.8, BreakerState: breaker.StateClosed})
	if res.Decision != models.DecisionQuarantine {
		t.Errorf("high drift: want Quarantine, got %q", res.Decision)
	}
}

// TestEngine_TraceIDPreserved verifies the TraceID passes through unchanged.
func TestEngine_TraceIDPreserved(t *testing.T) {
	eng := New(nil)
	res := eng.Evaluate(context.Background(), models.EvaluationContext{TraceID: "trace-abc123"})
	if res.TraceID != "trace-abc123" {
		t.Errorf("TraceID not preserved: got %q", res.TraceID)
	}
}
