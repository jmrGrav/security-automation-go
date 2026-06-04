package invariants_test

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/invariants"
	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestValidate_NilSnapshot_ReturnsViolation(t *testing.T) {
	e := invariants.New()
	violations := e.Validate(context.Background(), nil)
	if len(violations) == 0 {
		t.Fatal("expected at least one violation for nil snapshot")
	}
	if violations[0].Type != invariants.ViolationGraphIntegrity {
		t.Errorf("expected ViolationGraphIntegrity, got %q", violations[0].Type)
	}
}

func TestValidate_EmptySnapshot_Clean(t *testing.T) {
	e := invariants.New()
	snap := &snapshot.Snapshot{}
	violations := e.Validate(context.Background(), snap)
	if len(violations) != 0 {
		t.Errorf("expected no violations for empty snapshot, got %d: %+v", len(violations), violations)
	}
}

func TestValidate_DuplicateSIK_Detected(t *testing.T) {
	e := invariants.New()
	snap := &snapshot.Snapshot{
		Collection: snapshot.ResourceCollection{
			Objects: []snapshot.NormalizedObject{
				{StableIdentityKey: "ip:ip:1.2.3.4:block", ObjectID: "id-1"},
				{StableIdentityKey: "ip:ip:1.2.3.4:block", ObjectID: "id-2"}, // duplicate SIK
			},
		},
	}

	violations := e.Validate(context.Background(), snap)
	found := false
	for _, v := range violations {
		if v.Type == invariants.ViolationStableIDConflict {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ViolationStableIDConflict for duplicate SIK, violations: %+v", violations)
	}
}

func TestValidate_DuplicateObjectID_Detected(t *testing.T) {
	e := invariants.New()
	snap := &snapshot.Snapshot{
		Collection: snapshot.ResourceCollection{
			Objects: []snapshot.NormalizedObject{
				{StableIdentityKey: "sik-1", ObjectID: "shared-obj-id"},
				{StableIdentityKey: "sik-2", ObjectID: "shared-obj-id"}, // duplicate ObjectID, different SIK
			},
		},
	}

	violations := e.Validate(context.Background(), snap)
	found := false
	for _, v := range violations {
		if v.Type == invariants.ViolationResourceUnique {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ViolationResourceUnique for duplicate ObjectID, violations: %+v", violations)
	}
}

func TestValidate_UniqueObjects_NoViolations(t *testing.T) {
	e := invariants.New()
	snap := &snapshot.Snapshot{
		Collection: snapshot.ResourceCollection{
			Objects: []snapshot.NormalizedObject{
				{StableIdentityKey: "sik-1", ObjectID: "id-1"},
				{StableIdentityKey: "sik-2", ObjectID: "id-2"},
				{StableIdentityKey: "sik-3", ObjectID: "id-3"},
			},
		},
	}

	violations := e.Validate(context.Background(), snap)
	if len(violations) != 0 {
		t.Errorf("expected no violations for unique objects, got %d: %+v", len(violations), violations)
	}
}
