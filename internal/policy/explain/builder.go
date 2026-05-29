package explain

import (
	"fmt"
	"time"

	"github.com/jm/security-automation-go/internal/policy/federation"
)

// Builder constructs a decision graph from various governance signals.
type Builder struct{}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) Build(decision federation.FederatedDecision) *DecisionGraph {
	g := &DecisionGraph{
		DecisionID: decision.TraceID, // Using TraceID as a root for now
		Timestamp:  time.Now().UTC(),
	}

	// 1. Root Decision Node
	root := DecisionNode{
		ID:     "final",
		Type:   NodeDecision,
		Label:  fmt.Sprintf("Final: %s", decision.FinalDecision),
		Status: string(decision.FinalDecision),
	}
	g.Nodes = append(g.Nodes, root)

	// 2. Contributors (Federated layers)
	for i, c := range decision.Contributors {
		nodeID := fmt.Sprintf("fed_%d", i)
		node := DecisionNode{
			ID:     nodeID,
			Type:   NodePolicy,
			Label:  fmt.Sprintf("%s Policy (%s)", c.Scope, c.Decision),
			Status: string(c.Decision),
			Metadata: map[string]any{
				"bundle_id": c.BundleID,
				"reason":    c.Reason,
				"rule_id":   c.RuleID,
			},
		}
		g.Nodes = append(g.Nodes, node)
		g.Edges = append(g.Edges, DecisionEdge{From: nodeID, To: "final"})
	}

	// 3. Add generic inputs if metadata is available
	// (Eventually we'd add nodes for Governor, Drift, etc. based on input)

	return g
}
