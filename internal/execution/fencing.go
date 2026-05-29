package execution

import (
	"context"

	"github.com/jm/security-automation-go/internal/apperr"
	rtmodels "github.com/jm/security-automation-go/internal/runtime/models"
)

type FencingValidator interface {
	ValidateMutation(ctx context.Context, op MutationOperation) error
}

type LeaseStoreFencingValidator struct {
	leases interface {
		GetActiveLease(ctx context.Context, scopeID string, action string) (*rtmodels.Lease, error)
	}
	requireFencing bool
}

func NewLeaseStoreFencingValidator(leases interface {
	GetActiveLease(ctx context.Context, scopeID string, action string) (*rtmodels.Lease, error)
}) *LeaseStoreFencingValidator {
	return &LeaseStoreFencingValidator{leases: leases}
}

func (v *LeaseStoreFencingValidator) RequireFencing(required bool) *LeaseStoreFencingValidator {
	v.requireFencing = required
	return v
}

func (v *LeaseStoreFencingValidator) RequiresFencing() bool {
	return v != nil && v.requireFencing
}

func (v *LeaseStoreFencingValidator) ValidateMutation(ctx context.Context, op MutationOperation) error {
	const fn = "execution.LeaseStoreFencingValidator.ValidateMutation"
	if v == nil || v.leases == nil {
		return nil
	}
	if v.requireFencing {
		if op.ScopeID == "" {
			return apperr.New(fn, "missing scope_id for fenced mutation")
		}
		if op.LeaseID == "" || op.FencingToken == 0 {
			return apperr.New(fn, "missing fencing metadata")
		}
	}
	if op.LeaseID == "" && op.FencingToken == 0 {
		return nil
	}
	if op.ScopeID == "" {
		return apperr.New(fn, "missing scope_id for fenced mutation")
	}
	if op.LeaseID == "" || op.FencingToken == 0 {
		return apperr.New(fn, "incomplete fencing metadata")
	}
	action := op.LeaseAction
	if action == "" {
		action = "reconcile"
	}
	active, err := v.leases.GetActiveLease(ctx, op.ScopeID, action)
	if err != nil {
		return apperr.Wrap(fn, err)
	}
	if active == nil {
		return apperr.Newf(fn, "no active lease for scope %s action %s", op.ScopeID, action)
	}
	if active.ID != op.LeaseID || active.FencingToken != op.FencingToken {
		return apperr.Newf(fn, "stale fencing token for scope %s action %s", op.ScopeID, action)
	}
	return nil
}
