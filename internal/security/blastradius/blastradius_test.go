package blastradius

import (
	"testing"

	"github.com/jm/security-automation-go/internal/security/trust"
)

func TestEvaluateBlocksProtectedNetworkPropagation(t *testing.T) {
	verdict := Evaluate([]ProposedAction{
		{
			ScopeID:         "scope-a",
			Action:          "cloudflare_ban",
			TargetIP:        "127.0.0.1",
			Count:           1,
			ConfidenceScore: 1.0,
		},
	}, trust.DefaultRegistry(), DefaultLimits())

	if verdict.Allowed {
		t.Fatal("expected protected loopback target to be blocked")
	}
	if !verdict.RequiresReview {
		t.Fatal("expected review requirement")
	}
}

func TestEvaluateBlocksLowConfidenceCrossScope(t *testing.T) {
	verdict := Evaluate([]ProposedAction{
		{
			ScopeID:         "scope-a",
			Action:          "cloudflare_ban",
			CrossScope:      true,
			Count:           1,
			ConfidenceScore: 0.50,
		},
	}, trust.DefaultRegistry(), DefaultLimits())

	if verdict.Allowed {
		t.Fatal("expected low-confidence cross-scope action to be blocked")
	}
}
