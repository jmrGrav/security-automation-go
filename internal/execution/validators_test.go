package execution

import (
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestOwnershipValidator_Validate(t *testing.T) {
	reg := resources.NewRegistry()

	// Register an externally owned resource
	reg.Register(resources.Descriptor{
		Type:         "external_rule",
		DefaultOwner: resources.OwnershipExternallyOwned,
	})

	val := NewOwnershipValidator(reg)

	// 1. Fully managed should pass
	opOk := MutationOperation{
		ResourceType:      string(snapshot.ResourceIPAccessRules),
		StableIdentityKey: "ip:1.1.1.1",
	}
	if err := val.Validate(opOk); err != nil {
		t.Errorf("expected fully managed to pass, got %v", err)
	}

	// 2. Externally owned should fail
	opErr := MutationOperation{
		ResourceType:      "external_rule",
		StableIdentityKey: "ext:1",
	}
	err := val.Validate(opErr)
	if err == nil {
		t.Error("expected error for externally owned resource")
	}
}

func TestDriftValidator_Validate(t *testing.T) {
	val := NewDriftValidator()

	current := &snapshot.Snapshot{
		Collection: snapshot.ResourceCollection{
			Objects: []snapshot.NormalizedObject{
				{StableIdentityKey: "exists"},
			},
		},
	}

	// 1. Create something that already exists should fail
	opCreate := MutationOperation{Type: "create", StableIdentityKey: "exists"}
	if err := val.Validate(opCreate, current); err == nil {
		t.Error("expected drift error for duplicate creation")
	}

	// 2. Delete something that doesn't exist should fail
	opDelete := MutationOperation{Type: "delete", StableIdentityKey: "missing"}
	if err := val.Validate(opDelete, current); err == nil {
		t.Error("expected drift error for missing deletion")
	}

	// 3. Normal path should pass
	opOk := MutationOperation{Type: "create", StableIdentityKey: "new"}
	if err := val.Validate(opOk, current); err != nil {
		t.Errorf("expected success, got %v", err)
	}
}
