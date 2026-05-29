package engine

import (
	"context"
	"fmt"
	"strings"

	"github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
)

// Engine is the central policy evaluation service.
type Engine struct {
	policies []models.Policy
}

func New(policies []models.Policy) *Engine {
	return &Engine{policies: policies}
}

// Evaluate checks the given context against all enabled policies.
func (e *Engine) Evaluate(ctx context.Context, evalCtx models.EvaluationContext) models.AdmissionDecision {
	decision := models.AdmissionDecision{
		Allowed:  true,
		Decision: models.DecisionAllow,
		TraceID:  evalCtx.TraceID,
	}

	for _, p := range e.policies {
		if !p.Enabled {
			continue
		}

		for _, r := range p.Rules {
			if r.Target != evalCtx.TargetType && r.Target != "*" {
				continue
			}

			if e.matches(r, evalCtx) {
				violation := models.PolicyViolation{
					PolicyID:    p.ID,
					RuleID:      r.ID,
					Description: r.Description,
				}
				decision.Violations = append(decision.Violations, violation)

				// Conflict resolution: most restrictive wins (Deny > RequireApproval > Quarantine > Warn > Allow)
				if e.isMoreRestrictive(r.Decision, decision.Decision) {
					decision.Decision = r.Decision
					decision.Reason = r.Description
				}
			}
		}
	}

	if decision.Decision == models.DecisionDeny {
		decision.Allowed = false
	}

	return decision
}

func (e *Engine) matches(r models.Rule, ctx models.EvaluationContext) bool {
	// Simple rule matching logic for Phase 1.
	// In production, this would use OPA (Rego) or CEL.

	switch r.ID {
	case "deny-on-breaker-open":
		return ctx.BreakerState == breaker.StateOpen
	case "quarantine-on-high-drift":
		return ctx.Drift > 0.5 // 50% drift threshold
	case "require-approval-on-large-mutation":
		return ctx.MutationCount > 100
	case "deny-outside-maintenance-window":
		return !ctx.InMaintenance
	default:
		// Fallback for custom condition strings (very limited)
		if strings.Contains(r.Condition, "mutation_count >") {
			var limit int
			fmt.Sscanf(r.Condition, "mutation_count > %d", &limit)
			return ctx.MutationCount > limit
		}
	}

	return false
}

func (e *Engine) isMoreRestrictive(new, current models.Decision) bool {
	priority := map[models.Decision]int{
		models.DecisionDeny:            4,
		models.DecisionRequireApproval: 3,
		models.DecisionQuarantine:      2,
		models.DecisionWarn:            1,
		models.DecisionAllow:           0,
	}
	return priority[new] > priority[current]
}
