package storage

import (
	"context"
	"time"

	rolevidence "github.com/jm/security-automation-go/internal/policy/replay/evidence"
	rtmodels "github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
)

// RuntimeStateStore manages the persistent state of a reconciliation scope.
type RuntimeStateStore interface {
	Load(ctx context.Context) (rtmodels.RuntimeState, error)
	Save(ctx context.Context, state rtmodels.RuntimeState) error
}

// LeaseStore manages distributed execution leases.
type LeaseStore interface {
	GetActiveLease(ctx context.Context, scopeID string, action string) (*rtmodels.Lease, error)
	AcquireLease(ctx context.Context, scopeID string, lease rtmodels.Lease) error
	RenewLease(ctx context.Context, scopeID string, leaseID string, owner string, epochID string, fencingToken int64, expiresAt time.Time) error
	ReleaseLease(ctx context.Context, scopeID string, leaseID string, owner string) error
}

// EvidenceStore manages append-only governance decision logs.
type EvidenceStore interface {
	Append(ctx context.Context, ev rolevidence.GovernanceEvidence) error
	Get(ctx context.Context, id string) (rolevidence.GovernanceEvidence, error)
	List(ctx context.Context) ([]rolevidence.GovernanceEvidence, error)
}

// OwnershipStore manages sovereignty claims over resources.
type OwnershipStore interface {
	GetClaim(ctx context.Context, resourceID string) (ownership.OwnershipClaim, error)
	SetClaim(ctx context.Context, claim ownership.OwnershipClaim) error
	ListClaims(ctx context.Context) ([]ownership.OwnershipClaim, error)
	GetLineage(ctx context.Context, eventID string) (ownership.LineageEvent, bool, error)
	AppendLineage(ctx context.Context, event ownership.LineageEvent) error
	ListLineage(ctx context.Context, scopeID string, resourceID string, limit int) ([]ownership.LineageEvent, error)
	ListLineageCursor(ctx context.Context, scopeID string, resourceID string, beforeCreatedAt time.Time, beforeID string, limit int) ([]ownership.LineageEvent, error)
}
