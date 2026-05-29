package explain

import (
	"fmt"
	"strings"
	"time"
)

type NodeType string

const (
	NodeInput     NodeType = "input"
	NodeOwnership NodeType = "ownership"
	NodePolicy    NodeType = "policy"
	NodeGovernor  NodeType = "governor"
	NodeDrift     NodeType = "drift"
	NodeDecision  NodeType = "decision"
)

// DecisionNode represents a single factor in a governance decision.
type DecisionNode struct {
	ID       string         `json:"id"`
	Type     NodeType       `json:"type"`
	Label    string         `json:"label"`
	Status   string         `json:"status"` // allow, deny, neutral, error
	Metadata map[string]any `json:"metadata,omitempty"`
}

// DecisionEdge represents a causal link between decision nodes.
type DecisionEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Label string `json:"label,omitempty"`
}

// DecisionGraph is a causal DAG explaining a policy result.
type DecisionGraph struct {
	DecisionID string         `json:"decision_id"`
	Timestamp  time.Time      `json:"timestamp"`
	Nodes      []DecisionNode `json:"nodes"`
	Edges      []DecisionEdge `json:"edges"`
}

// ToMermaid exports the graph to a Mermaid string.
func (g *DecisionGraph) ToMermaid() string {
	var sb strings.Builder
	sb.WriteString("graph TD\n")

	for _, n := range g.Nodes {
		style := ""
		switch n.Status {
		case "deny":
			style = ":::denied"
		case "allow":
			style = ":::allowed"
		}
		sb.WriteString(fmt.Sprintf("  %s[%s]%s\n", n.ID, n.Label, style))
	}

	for _, e := range g.Edges {
		if e.Label != "" {
			sb.WriteString(fmt.Sprintf("  %s -->|%s| %s\n", e.From, e.Label, e.To))
		} else {
			sb.WriteString(fmt.Sprintf("  %s --> %s\n", e.From, e.To))
		}
	}

	sb.WriteString("\n  classDef denied fill:#f96,stroke:#333,stroke-width:2px;\n")
	sb.WriteString("  classDef allowed fill:#9f6,stroke:#333,stroke-width:2px;\n")

	return sb.String()
}
