package ha

import (
	"context"

	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/scope"
)

// FencingToken is a monotonic value used to prevent stale writers.
type FencingToken struct {
	ScopeID    string `json:"scope_id"`
	Epoch      int64  `json:"epoch"`
	Generation int64  `json:"generation"`
	OwnerID    string `json:"owner_id"`
}

// CoordinationBackend defines the interface for distributed coordination.
type CoordinationBackend interface {
	// CampaignLeader attempts to become the leader for a given scope.
	CampaignLeader(ctx context.Context, s scope.RuntimeScope, ownerID string) (chan struct{}, error)

	// GetFencingToken returns the latest persistent token for a scope.
	GetFencingToken(ctx context.Context, scopeID string) (FencingToken, error)

	// StoreFencingToken persists a new token, usually during epoch increment.
	StoreFencingToken(ctx context.Context, token FencingToken) error

	// Epoch management
	GetEpoch(ctx context.Context, s scope.RuntimeScope) (models.Epoch, error)
	IncrementEpoch(ctx context.Context, s scope.RuntimeScope) (models.Epoch, error)
}

// LeaseCoordinator manages scope-level locks with heartbeats.
type LeaseCoordinator struct {
	backend CoordinationBackend
	ownerID string
}

func NewLeaseCoordinator(backend CoordinationBackend, ownerID string) *LeaseCoordinator {
	return &LeaseCoordinator{
		backend: backend,
		ownerID: ownerID,
	}
}
