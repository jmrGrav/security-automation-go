package graph

import (
	"fmt"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// DependencyGraph manages a Directed Acyclic Graph of resource types.
type DependencyGraph struct {
	nodes map[snapshot.ResourceType][]snapshot.ResourceType
}

func New() *DependencyGraph {
	return &DependencyGraph{
		nodes: make(map[snapshot.ResourceType][]snapshot.ResourceType),
	}
}

// AddLink adds a dependency link: 'from' depends on 'to'.
func (g *DependencyGraph) AddLink(from, to snapshot.ResourceType) {
	g.nodes[from] = append(g.nodes[from], to)
}

// Validate checks for cycles and return the topological order.
func (g *DependencyGraph) ResolveOrder() ([]snapshot.ResourceType, error) {
	const op = "snapshot.graph.ResolveOrder"

	// 1. Identify all unique nodes
	allTypes := make(map[snapshot.ResourceType]bool)
	for from, toList := range g.nodes {
		allTypes[from] = true
		for _, to := range toList {
			allTypes[to] = true
		}
	}

	var result []snapshot.ResourceType
	visited := make(map[snapshot.ResourceType]bool)
	temp := make(map[snapshot.ResourceType]bool)

	var visit func(n snapshot.ResourceType) error
	visit = func(n snapshot.ResourceType) error {
		if temp[n] {
			return apperr.Newf(op, "cycle detected involving %s", n)
		}
		if !visited[n] {
			temp[n] = true
			for _, dep := range g.nodes[n] {
				if err := visit(dep); err != nil {
					return err
				}
			}
			visited[n] = true
			temp[n] = false
			result = append(result, n)
		}
		return nil
	}

	for n := range allTypes {
		if !visited[n] {
			if err := visit(n); err != nil {
				return nil, err
			}
		}
	}

	// Result is in reverse topological order (dependencies first)
	return result, nil
}

func (g *DependencyGraph) String() string {
	return fmt.Sprintf("%v", g.nodes)
}
