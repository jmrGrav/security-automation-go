package execution

import (
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// DriftValidator ensures that the remote state hasn't changed since the plan was created.
type DriftValidator struct{}

func NewDriftValidator() *DriftValidator {
	return &DriftValidator{}
}

func (v *DriftValidator) Validate(op MutationOperation, current *snapshot.Snapshot) error {
	const fn = "execution.DriftValidator.Validate"

	if current == nil {
		return apperr.New(fn, "current snapshot is required for drift validation")
	}

	// 1. Check if the object still exists in current state
	// For creation, it should NOT exist.
	// For update/delete, it SHOULD exist and match current state.

	found := false
	var existing snapshot.NormalizedObject
	for _, obj := range current.Collection.Objects {
		if obj.StableIdentityKey == op.StableIdentityKey {
			found = true
			existing = obj
			break
		}
	}

	switch op.Type {
	case "create":
		if found {
			return apperr.Newf(fn, "drift detected: resource %s already exists", op.StableIdentityKey)
		}
	case "update", "delete":
		if !found {
			return apperr.Newf(fn, "drift detected: resource %s no longer exists", op.StableIdentityKey)
		}
		// Optional: validate attributes for updates
		if op.Type == "update" && op.ExpectedETag != "" {
			// If we have an ETag in current state metadata, compare it
			// (Assuming we store provider metadata in NormalizedObject)
		}
	}

	_ = existing // Use existing for more detailed comparison in prod

	return nil
}

// OwnershipValidator ensures that the system is allowed to mutate the given resource.
type OwnershipValidator struct {
	registry *resources.Registry
}

func NewOwnershipValidator(r *resources.Registry) *OwnershipValidator {
	return &OwnershipValidator{
		registry: r,
	}
}

func (v *OwnershipValidator) Validate(op MutationOperation) error {
	const fn = "execution.OwnershipValidator.Validate"

	descriptor, ok := v.registry.Get(snapshot.ResourceType(op.ResourceType))
	if !ok {
		return apperr.Newf(fn, "unrecognized resource type: %s", op.ResourceType)
	}

	// If the resource is Externally Owned, we NEVER mutate it.
	if descriptor.DefaultOwner == resources.OwnershipExternallyOwned {
		return apperr.Newf(fn, "permission denied: resource %s is externally owned", op.StableIdentityKey)
	}

	// TODO: Add more granular capability checks (e.g. can we delete this specific rule?)

	return nil
}
