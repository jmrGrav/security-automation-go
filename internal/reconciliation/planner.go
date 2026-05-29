package reconciliation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/jm/security-automation-go/internal/snapshot"
)

type GenericPlanner struct{}

func NewGenericPlanner() *GenericPlanner {
	return &GenericPlanner{}
}

func (p *GenericPlanner) Plan(current *snapshot.Snapshot, target []snapshot.NormalizedObject) (*Plan, error) {
	plan := &Plan{
		PlanID:     fmt.Sprintf("plan-%d", time.Now().UnixNano()),
		CreatedAt:  time.Now().UTC(),
		Status:     "draft",
		Operations: []Operation{},
	}

	if current != nil {
		plan.SnapshotID = current.SnapshotID
	}

	currentMap := make(map[string]snapshot.NormalizedObject)
	if current != nil {
		for _, obj := range current.Collection.Objects {
			currentMap[obj.StableIdentityKey] = obj
		}
	}

	targetMap := make(map[string]snapshot.NormalizedObject)
	for _, obj := range target {
		targetMap[obj.StableIdentityKey] = obj
	}

	// Identify deletions (exists in current, not in target)
	if current != nil {
		for _, obj := range current.Collection.Objects {
			if _, ok := targetMap[obj.StableIdentityKey]; !ok {
				plan.Operations = append(plan.Operations, Operation{
					OperationID:    p.deriveOpID(OpDelete, obj.StableIdentityKey),
					Type:           OpDelete,
					TargetID:       obj.StableIdentityKey,
					ResourceType:   obj.ObjectType,
					Reason:         "not present in target state",
					IdempotencyKey: p.deriveIdempotencyKey(OpDelete, obj.StableIdentityKey, nil),
					State:          StatePlanned,
				})
			}
		}
	}

	// Identify additions and updates
	for _, obj := range target {
		curr, ok := currentMap[obj.StableIdentityKey]
		if !ok {
			// Addition
			plan.Operations = append(plan.Operations, Operation{
				OperationID:    p.deriveOpID(OpCreate, obj.StableIdentityKey),
				Type:           OpCreate,
				TargetID:       obj.StableIdentityKey,
				ResourceType:   obj.ObjectType,
				Reason:         "present in target but not in current state",
				IdempotencyKey: p.deriveIdempotencyKey(OpCreate, obj.StableIdentityKey, obj.Attributes),
				State:          StatePlanned,
				Payload:        obj.Attributes,
			})
		} else {
			// Check for update (compare attributes)
			if !p.attributesEqual(curr.Attributes, obj.Attributes) {
				plan.Operations = append(plan.Operations, Operation{
					OperationID:    p.deriveOpID(OpUpdate, obj.StableIdentityKey),
					Type:           OpUpdate,
					TargetID:       obj.StableIdentityKey,
					ResourceType:   obj.ObjectType,
					Reason:         "attributes differ between current and target state",
					IdempotencyKey: p.deriveIdempotencyKey(OpUpdate, obj.StableIdentityKey, obj.Attributes),
					State:          StatePlanned,
					Payload:        obj.Attributes,
					Preconditions:  curr.Attributes, // Expecting current state as precondition
				})
			}
		}
	}

	// Sort operations for determinism: Delete -> Update -> Create (to avoid conflicts if IDs overlap)
	// Within types, sort by TargetID.
	sort.Slice(plan.Operations, func(i, j int) bool {
		if plan.Operations[i].Type != plan.Operations[j].Type {
			return p.typePriority(plan.Operations[i].Type) < p.typePriority(plan.Operations[j].Type)
		}
		return plan.Operations[i].TargetID < plan.Operations[j].TargetID
	})

	plan.DryRunSummary = fmt.Sprintf("Planned %d operations: %d creations, %d updates, %d deletions",
		len(plan.Operations),
		p.countType(plan.Operations, OpCreate),
		p.countType(plan.Operations, OpUpdate),
		p.countType(plan.Operations, OpDelete),
	)

	return plan, nil
}

func (p *GenericPlanner) typePriority(t OperationType) int {
	switch t {
	case OpDelete:
		return 1
	case OpUpdate:
		return 2
	case OpCreate:
		return 3
	default:
		return 4
	}
}

func (p *GenericPlanner) countType(ops []Operation, t OperationType) int {
	count := 0
	for _, op := range ops {
		if op.Type == t {
			count++
		}
	}
	return count
}

func (p *GenericPlanner) attributesEqual(a, b map[string]any) bool {
	// Simple attribute comparison. In a real scenario, this might need
	// more sophisticated logic depending on the resource type.
	return snapshot.CanonicalJSON(a) == snapshot.CanonicalJSON(b)
}

func (p *GenericPlanner) deriveOpID(t OperationType, targetID string) string {
	sum := sha256.Sum256([]byte(string(t) + ":" + targetID + ":" + time.Now().Format(time.RFC3339Nano)))
	return fmt.Sprintf("op-%s", hex.EncodeToString(sum[:8]))
}

func (p *GenericPlanner) deriveIdempotencyKey(t OperationType, targetID string, payload any) string {
	payloadStr := ""
	if payload != nil {
		payloadStr = snapshot.CanonicalJSON(payload)
	}
	sum := sha256.Sum256([]byte(string(t) + ":" + targetID + ":" + payloadStr))
	return hex.EncodeToString(sum[:])
}
