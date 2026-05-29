package reconciliation

import (
	"testing"

	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestGenericPlanner_Plan(t *testing.T) {
	planner := NewGenericPlanner()

	// 1. Current state: a=1, b=2
	current := &snapshot.Snapshot{
		SnapshotID: "snap-1",
		Collection: snapshot.ResourceCollection{
			Objects: []snapshot.NormalizedObject{
				{StableIdentityKey: "a", ObjectType: "rule", Attributes: map[string]any{"value": float64(1)}},
				{StableIdentityKey: "b", ObjectType: "rule", Attributes: map[string]any{"value": float64(2)}},
			},
		},
	}

	// 2. Target state: b=2 (unchanged), c=3 (new), a=10 (updated)
	target := []snapshot.NormalizedObject{
		{StableIdentityKey: "b", ObjectType: "rule", Attributes: map[string]any{"value": float64(2)}},
		{StableIdentityKey: "c", ObjectType: "rule", Attributes: map[string]any{"value": float64(3)}},
		{StableIdentityKey: "a", ObjectType: "rule", Attributes: map[string]any{"value": float64(10)}},
	}

	plan, err := planner.Plan(current, target)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}

	expectedOps := 2 // Update 'a', Create 'c'
	if len(plan.Operations) != expectedOps {
		t.Fatalf("expected %d operations, got %d: %#v", expectedOps, len(plan.Operations), plan.Operations)
	}

	foundUpdateA := false
	foundCreateC := false
	for _, op := range plan.Operations {
		if op.Type == OpUpdate && op.TargetID == "a" {
			foundUpdateA = true
		}
		if op.Type == OpCreate && op.TargetID == "c" {
			foundCreateC = true
		}
	}

	if !foundUpdateA {
		t.Error("expected update operation for 'a'")
	}
	if !foundCreateC {
		t.Error("expected create operation for 'c'")
	}
}

func TestGenericPlanner_Plan_Deletions(t *testing.T) {
	planner := NewGenericPlanner()

	current := &snapshot.Snapshot{
		SnapshotID: "snap-2",
		Collection: snapshot.ResourceCollection{
			Objects: []snapshot.NormalizedObject{
				{StableIdentityKey: "x", ObjectType: "rule", Attributes: map[string]any{"v": 1}},
				{StableIdentityKey: "y", ObjectType: "rule", Attributes: map[string]any{"v": 2}},
			},
		},
	}

	// Target: only 'x' remains
	target := []snapshot.NormalizedObject{
		{StableIdentityKey: "x", ObjectType: "rule", Attributes: map[string]any{"v": 1}},
	}

	plan, err := planner.Plan(current, target)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}

	if len(plan.Operations) != 1 {
		t.Fatalf("expected 1 deletion, got %d", len(plan.Operations))
	}

	if plan.Operations[0].Type != OpDelete || plan.Operations[0].TargetID != "y" {
		t.Errorf("unexpected operation: %#v", plan.Operations[0])
	}
}

func TestGenericPlanner_Plan_Determinism(t *testing.T) {
	planner := NewGenericPlanner()

	current := &snapshot.Snapshot{
		SnapshotID: "snap-3",
		Collection: snapshot.ResourceCollection{
			Objects: []snapshot.NormalizedObject{
				{StableIdentityKey: "del1", ObjectType: "rule"},
				{StableIdentityKey: "upd1", ObjectType: "rule", Attributes: map[string]any{"v": 1}},
			},
		},
	}

	target := []snapshot.NormalizedObject{
		{StableIdentityKey: "upd1", ObjectType: "rule", Attributes: map[string]any{"v": 2}},
		{StableIdentityKey: "new1", ObjectType: "rule"},
	}

	plan1, _ := planner.Plan(current, target)
	plan2, _ := planner.Plan(current, target)

	if len(plan1.Operations) != len(plan2.Operations) {
		t.Fatal("plans should have same number of operations")
	}

	for i := range plan1.Operations {
		if plan1.Operations[i].Type != plan2.Operations[i].Type {
			t.Errorf("operation %d type mismatch: %s != %s", i, plan1.Operations[i].Type, plan2.Operations[i].Type)
		}
		if plan1.Operations[i].TargetID != plan2.Operations[i].TargetID {
			t.Errorf("operation %d target mismatch: %s != %s", i, plan1.Operations[i].TargetID, plan2.Operations[i].TargetID)
		}
	}
}
