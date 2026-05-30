package opa_test

import (
	"context"
	"log/slog"
	"os"
	"testing"

	"github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/policy/opa"
)

var discardLogger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

const allowAllPolicy = `
package cfsync.admission
default decision = "allow"
`

const denyAllPolicy = `
package cfsync.admission
default decision = "deny"
`

// conditionalDenyPolicy uses an actual field from RuntimeContext.
const conditionalDenyPolicy = `
package cfsync.admission
default decision = "allow"
decision = "deny" {
    input.runtime.breaker_state == "open"
}
`

const requireApprovalPolicy = `
package cfsync.admission
default decision = "allow"
decision = "require_approval" {
    input.runtime.is_dry_run == true
}
`

// TestOPA_InvalidRegoSyntax verifies that construction fails gracefully on
// malformed Rego, returning an error rather than panicking.
func TestOPA_InvalidRegoSyntax(t *testing.T) {
	_, err := opa.NewEngine(context.Background(), discardLogger, "this is not valid rego {{{")
	if err == nil {
		t.Error("expected error on invalid Rego syntax, got nil")
	}
}

// TestOPA_AllowDecision verifies the engine returns Allow on a permissive policy.
func TestOPA_AllowDecision(t *testing.T) {
	eng, err := opa.NewEngine(context.Background(), discardLogger, allowAllPolicy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	decision, _, err := eng.Evaluate(context.Background(), models.PolicyInput{})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if decision != models.DecisionAllow {
		t.Errorf("want Allow, got %q", decision)
	}
}

// TestOPA_DenyDecision verifies the engine returns Deny on a deny-all policy.
func TestOPA_DenyDecision(t *testing.T) {
	eng, err := opa.NewEngine(context.Background(), discardLogger, denyAllPolicy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	decision, _, err := eng.Evaluate(context.Background(), models.PolicyInput{})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if decision != models.DecisionDeny {
		t.Errorf("want Deny, got %q", decision)
	}
}

// TestOPA_ConditionalDeny verifies input-driven conditional deny.
// Uses RuntimeContext.BreakerState (an actual PolicyInput field).
func TestOPA_ConditionalDeny(t *testing.T) {
	eng, err := opa.NewEngine(context.Background(), discardLogger, conditionalDenyPolicy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	ctx := context.Background()

	// Breaker closed → allow
	dec, _, err := eng.Evaluate(ctx, models.PolicyInput{
		Runtime: models.RuntimeContext{BreakerState: "closed"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec != models.DecisionAllow {
		t.Errorf("want Allow when breaker closed, got %q", dec)
	}

	// Breaker open → deny
	dec, _, err = eng.Evaluate(ctx, models.PolicyInput{
		Runtime: models.RuntimeContext{BreakerState: "open"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec != models.DecisionDeny {
		t.Errorf("want Deny when breaker open, got %q", dec)
	}
}

// TestOPA_RequireApproval verifies require_approval decision.
func TestOPA_RequireApproval(t *testing.T) {
	eng, err := opa.NewEngine(context.Background(), discardLogger, requireApprovalPolicy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Dry-run = true → require_approval
	dec, reason, err := eng.Evaluate(context.Background(), models.PolicyInput{
		Runtime: models.RuntimeContext{IsDryRun: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec != models.DecisionRequireApproval {
		t.Errorf("want RequireApproval, got %q (reason: %s)", dec, reason)
	}

	// Dry-run = false → allow
	dec, _, err = eng.Evaluate(context.Background(), models.PolicyInput{
		Runtime: models.RuntimeContext{IsDryRun: false},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec != models.DecisionAllow {
		t.Errorf("want Allow when not dry-run, got %q", dec)
	}
}

// TestOPA_EmptyResultDefaultsToAllow verifies that a policy returning no
// decision binding defaults to Allow.
func TestOPA_EmptyResultDefaultsToAllow(t *testing.T) {
	emptyPolicy := `package cfsync.admission`
	eng, err := opa.NewEngine(context.Background(), discardLogger, emptyPolicy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	dec, _, err := eng.Evaluate(context.Background(), models.PolicyInput{})
	if err != nil {
		t.Fatalf("Evaluate error: %v", err)
	}
	if dec != models.DecisionAllow {
		t.Errorf("empty result must default to Allow, got %q", dec)
	}
}

// TestOPA_ContextCancellationHandled verifies that a cancelled context does not panic.
func TestOPA_ContextCancellationHandled(t *testing.T) {
	eng, err := opa.NewEngine(context.Background(), discardLogger, allowAllPolicy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, _, _ = eng.Evaluate(ctx, models.PolicyInput{})
}

// TestOPA_MultipleEvaluations verifies the engine is reusable across calls
// (the PreparedEvalQuery is stateless between invocations).
func TestOPA_MultipleEvaluations(t *testing.T) {
	eng, err := opa.NewEngine(context.Background(), discardLogger, conditionalDenyPolicy)
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		dec, _, err := eng.Evaluate(ctx, models.PolicyInput{
			Runtime: models.RuntimeContext{BreakerState: "closed"},
		})
		if err != nil {
			t.Fatalf("iteration %d: %v", i, err)
		}
		if dec != models.DecisionAllow {
			t.Errorf("iteration %d: want Allow, got %q", i, dec)
		}
	}
}
