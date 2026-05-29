package invariants

import (
	"context"

	"github.com/jm/security-automation-go/internal/snapshot"
)

type ViolationType string

const (
	ViolationGraphIntegrity   ViolationType = "graph_integrity"
	ViolationOwnershipBound   ViolationType = "ownership_boundary"
	ViolationResourceUnique   ViolationType = "resource_uniqueness"
	ViolationStableIDConflict ViolationType = "stable_id_conflict"
	ViolationPhaseOrdering    ViolationType = "phase_ordering"
)

type Violation struct {
	Type        ViolationType
	Description string
	Resource    string // SIK
}

// Engine evaluates system invariants against a snapshot.
type Engine struct{}

func New() *Engine {
	return &Engine{}
}

func (e *Engine) Validate(ctx context.Context, snap *snapshot.Snapshot) []Violation {
	var violations []Violation

	// 1. Stable Identity Uniqueness
	seenSIKs := make(map[string]bool)
	for _, obj := range snap.Collection.Objects {
		if seenSIKs[obj.StableIdentityKey] {
			violations = append(violations, Violation{
				Type:        ViolationStableIDConflict,
				Description: "duplicate stable identity key detected",
				Resource:    obj.StableIdentityKey,
			})
		}
		seenSIKs[obj.StableIdentityKey] = true
	}

	// 2. Resource Uniqueness (Provider ObjectID uniqueness)
	seenIDs := make(map[string]string)
	for _, obj := range snap.Collection.Objects {
		if obj.ObjectID == "" {
			continue
		}
		if otherSIK, exists := seenIDs[obj.ObjectID]; exists {
			violations = append(violations, Violation{
				Type:        ViolationResourceUnique,
				Description: "duplicate provider object ID detected for different SIKs: " + otherSIK,
				Resource:    obj.StableIdentityKey,
			})
		}
		seenIDs[obj.ObjectID] = obj.StableIdentityKey
	}

	// 3. Graph Integrity (DAG validation)
	// TODO: Integrate graph package

	return violations
}
