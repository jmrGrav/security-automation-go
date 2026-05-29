// Package blastradius enforces scoped propagation limits around automated
// security decisions. It answers a simple safety question: "even if this
// decision is wrong, how much can it hurt?"
package blastradius

import (
	"fmt"

	"github.com/jm/security-automation-go/internal/security/trust"
)

type Limits struct {
	MaxActionsPerMinute    int     `json:"max_actions_per_minute"`
	MaxCrossScopeActions   int     `json:"max_cross_scope_actions"`
	MaxTenantWideActions   int     `json:"max_tenant_wide_actions"`
	MinConfidenceForGlobal float64 `json:"min_confidence_for_global"`
}

type ProposedAction struct {
	ScopeID         string  `json:"scope_id"`
	TenantID        string  `json:"tenant_id"`
	TargetIP        string  `json:"target_ip,omitempty"`
	TargetService   string  `json:"target_service,omitempty"`
	Action          string  `json:"action"`
	CrossScope      bool    `json:"cross_scope"`
	TenantWide      bool    `json:"tenant_wide"`
	Count           int     `json:"count"`
	ConfidenceScore float64 `json:"confidence_score"`
}

type Verdict struct {
	Allowed           bool   `json:"allowed"`
	RequiresReview    bool   `json:"requires_review"`
	FreezeRecommended bool   `json:"freeze_recommended"`
	Reason            string `json:"reason"`
}

func DefaultLimits() Limits {
	return Limits{
		MaxActionsPerMinute:    10,
		MaxCrossScopeActions:   1,
		MaxTenantWideActions:   1,
		MinConfidenceForGlobal: 0.95,
	}
}

func Evaluate(actions []ProposedAction, registry *trust.Registry, limits Limits) Verdict {
	total := 0
	crossScope := 0
	tenantWide := 0

	for _, action := range actions {
		total += action.Count
		if action.CrossScope {
			crossScope += action.Count
		}
		if action.TenantWide {
			tenantWide += action.Count
		}
		if action.ConfidenceScore < limits.MinConfidenceForGlobal && (action.CrossScope || action.TenantWide) {
			return Verdict{
				Allowed:        false,
				RequiresReview: true,
				Reason:         "low-confidence action cannot propagate beyond scope",
			}
		}
		if action.TargetIP != "" {
			if matches := registry.MatchIP(action.TargetIP); len(matches) > 0 {
				return Verdict{
					Allowed:           false,
					RequiresReview:    true,
					FreezeRecommended: true,
					Reason:            fmt.Sprintf("target IP %s is protected (%s)", action.TargetIP, matches[0].Resource.Name),
				}
			}
		}
		if action.TargetService != "" {
			if matches := registry.MatchService(action.TargetService); len(matches) > 0 {
				return Verdict{
					Allowed:        false,
					RequiresReview: true,
					Reason:         fmt.Sprintf("target service %s is protected", action.TargetService),
				}
			}
		}
	}

	if total > limits.MaxActionsPerMinute {
		return Verdict{
			Allowed:           false,
			RequiresReview:    true,
			FreezeRecommended: true,
			Reason:            "action volume exceeds per-minute blast-radius limit",
		}
	}
	if crossScope > limits.MaxCrossScopeActions {
		return Verdict{
			Allowed:        false,
			RequiresReview: true,
			Reason:         "cross-scope propagation exceeds configured limit",
		}
	}
	if tenantWide > limits.MaxTenantWideActions {
		return Verdict{
			Allowed:        false,
			RequiresReview: true,
			Reason:         "tenant-wide propagation exceeds configured limit",
		}
	}

	return Verdict{Allowed: true}
}
