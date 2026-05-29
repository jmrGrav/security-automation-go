package reporting

import (
	"context"

	"github.com/jm/security-automation-go/internal/apperr"
	rtmodels "github.com/jm/security-automation-go/internal/runtime/models"
)

type LeaseStoreOutboxGuard struct {
	scopeID string
	action  string
	leases  interface {
		GetActiveLease(ctx context.Context, scopeID string, action string) (*rtmodels.Lease, error)
	}
}

func NewLeaseStoreOutboxGuard(scopeID string, action string, leases interface {
	GetActiveLease(ctx context.Context, scopeID string, action string) (*rtmodels.Lease, error)
}) *LeaseStoreOutboxGuard {
	if action == "" {
		action = "reconcile"
	}
	return &LeaseStoreOutboxGuard{
		scopeID: scopeID,
		action:  action,
		leases:  leases,
	}
}

func (g *LeaseStoreOutboxGuard) ValidateOutboxItem(ctx context.Context, _ ReportOutboxItem) error {
	const op = "reporting.LeaseStoreOutboxGuard.ValidateOutboxItem"
	if g == nil || g.leases == nil || g.scopeID == "" {
		return apperr.New(op, "missing outbox lease guard configuration")
	}
	lease, err := g.leases.GetActiveLease(ctx, g.scopeID, g.action)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if lease == nil || lease.IsExpired() {
		return apperr.Newf(op, "no active lease for scope %s action %s", g.scopeID, g.action)
	}
	return nil
}
