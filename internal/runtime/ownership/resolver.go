package ownership

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

// Resolver adjudicates sovereignty conflicts between domains.
type Resolver struct {
	mu      sync.RWMutex
	domains map[string]OwnershipDomain
	claims  map[string]OwnershipClaim // ResourceID -> Claim
	lineage LineageRecorder
	store   ClaimStore
}

type ClaimStore interface {
	GetClaim(ctx context.Context, resourceID string) (OwnershipClaim, error)
	SetClaim(ctx context.Context, claim OwnershipClaim) error
	ListClaims(ctx context.Context) ([]OwnershipClaim, error)
}

func NewResolver() *Resolver {
	return &Resolver{
		domains: make(map[string]OwnershipDomain),
		claims:  make(map[string]OwnershipClaim),
	}
}

func (r *Resolver) RegisterDomain(d OwnershipDomain) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.domains[d.ID] = d
}

func (r *Resolver) SetLineageRecorder(recorder LineageRecorder) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lineage = recorder
}

func (r *Resolver) SetClaimStore(store ClaimStore) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.store = store
}

// Resolve checks if the requesting domain is authorized to mutate the resource.
func (r *Resolver) Resolve(ctx context.Context, requestingDomainID, resourceID string, requiredRight Right) (ResolutionOutcome, error) {
	const op = "runtime.ownership.Resolve"

	r.mu.RLock()
	reqDomain, ok := r.domains[requestingDomainID]
	lineage := r.lineage
	memClaim, memExists := r.claims[resourceID]
	store := r.store
	r.mu.RUnlock()
	if !ok {
		return ResolutionOutcome{}, apperr.Newf(op, "unrecognized domain: %s", requestingDomainID)
	}

	record := func(outcome ResolutionOutcome, owner string, epoch int64) {
		if lineage == nil {
			return
		}
		now := time.Now().UTC()
		_ = lineage.Append(LineageEvent{
			ID:            NewLineageEventID("global", resourceID, now),
			ScopeID:       "global",
			ResourceID:    resourceID,
			DomainID:      requestingDomainID,
			EventType:     LineageEventResolve,
			Decision:      outcome.Action,
			RequiredRight: requiredRight,
			OwnerDomain:   owner,
			Epoch:         epoch,
			Reason:        outcome.Reason,
			DecisionHash:  BuildDecisionHash(LineageEventResolve, "global", resourceID, requestingDomainID, outcome.Action, outcome.Reason, requiredRight, owner, epoch),
			CreatedAt:     now,
		})
	}

	// 1. Check if resource has an active claim
	currentClaim, exists, err := r.getClaim(ctx, resourceID, memClaim, memExists, store)
	if err != nil {
		return ResolutionOutcome{}, apperr.Wrap(op, err)
	}
	if !exists {
		// No active claim, allow if domain has the capability
		if r.hasCapability(reqDomain, requiredRight) {
			out := ResolutionOutcome{Allowed: true, Action: "allow"}
			record(out, "", 0)
			return out, nil
		}
		out := ResolutionOutcome{Allowed: false, Action: "deny", Reason: "domain lacks capability"}
		record(out, "", 0)
		return out, nil
	}

	currentOwner := r.domains[currentClaim.DomainID]

	// 2. Check for Immutable trust (Cloudflare Managed)
	if currentOwner.Trust == TrustImmutable {
		out := ResolutionOutcome{
			Allowed: false,
			Action:  "readonly",
			Reason:  fmt.Sprintf("resource %s is immutable (owned by %s)", resourceID, currentOwner.ID),
			Owner:   currentOwner.ID,
		}
		record(out, currentOwner.ID, currentClaim.Epoch)
		return out, nil
	}

	// 3. Priority resolution
	if reqDomain.Priority > currentOwner.Priority {
		// Overriding lower priority owner
		if r.hasCapability(reqDomain, RightOverride) {
			out := ResolutionOutcome{Allowed: true, Action: "override", Owner: currentOwner.ID}
			record(out, currentOwner.ID, currentClaim.Epoch)
			return out, nil
		}
	} else if reqDomain.Priority < currentOwner.Priority {
		out := ResolutionOutcome{
			Allowed: false,
			Action:  "deny",
			Reason:  fmt.Sprintf("resource %s is owned by higher priority domain: %s", resourceID, currentOwner.ID),
			Owner:   currentOwner.ID,
		}
		record(out, currentOwner.ID, currentClaim.Epoch)
		return out, nil
	}

	// 4. Same priority or allowed takeover
	if r.hasCapability(reqDomain, requiredRight) {
		out := ResolutionOutcome{Allowed: true, Action: "allow", Owner: currentOwner.ID}
		record(out, currentOwner.ID, currentClaim.Epoch)
		return out, nil
	}

	out := ResolutionOutcome{Allowed: false, Action: "deny", Reason: "insufficient rights", Owner: currentOwner.ID}
	record(out, currentOwner.ID, currentClaim.Epoch)
	return out, nil
}

func (r *Resolver) hasCapability(d OwnershipDomain, right Right) bool {
	for _, cap := range d.Capabilities {
		if cap == right {
			return true
		}
	}
	return false
}

// Claim attempts to assert sovereignty over a resource.
func (r *Resolver) Claim(claim OwnershipClaim) error {
	r.mu.Lock()
	store := r.store
	lineage := r.lineage
	r.mu.Unlock()

	if store != nil {
		if err := store.SetClaim(context.Background(), claim); err != nil {
			return err
		}
	}
	r.mu.Lock()
	r.claims[claim.ResourceID] = claim
	r.mu.Unlock()
	if lineage != nil {
		now := time.Now().UTC()
		_ = lineage.Append(LineageEvent{
			ID:           NewLineageEventID(claim.ScopeID, claim.ResourceID, now),
			ScopeID:      claim.ScopeID,
			ResourceID:   claim.ResourceID,
			DomainID:     claim.DomainID,
			EventType:    LineageEventClaim,
			Epoch:        claim.Epoch,
			Decision:     "claim_set",
			DecisionHash: BuildDecisionHash(LineageEventClaim, claim.ScopeID, claim.ResourceID, claim.DomainID, "claim_set", "", "", "", claim.Epoch),
			CreatedAt:    now,
		})
	}
	return nil
}

// ListClaims returns all active sovereignty claims.
func (r *Resolver) ListClaims() []OwnershipClaim {
	r.mu.RLock()
	store := r.store
	memClaims := make([]OwnershipClaim, 0, len(r.claims))
	for _, c := range r.claims {
		memClaims = append(memClaims, c)
	}
	r.mu.RUnlock()

	if store != nil {
		if claims, err := store.ListClaims(context.Background()); err == nil {
			r.mu.Lock()
			r.claims = make(map[string]OwnershipClaim, len(claims))
			for _, c := range claims {
				r.claims[c.ResourceID] = c
			}
			r.mu.Unlock()
			return claims
		}
	}
	return memClaims
}

func (r *Resolver) getClaim(ctx context.Context, resourceID string, memClaim OwnershipClaim, memExists bool, store ClaimStore) (OwnershipClaim, bool, error) {
	if store != nil {
		claim, err := store.GetClaim(ctx, resourceID)
		if err != nil {
			return OwnershipClaim{}, false, err
		}
		if claim.ResourceID != "" {
			r.mu.Lock()
			r.claims[resourceID] = claim
			r.mu.Unlock()
			return claim, true, nil
		}
		return OwnershipClaim{}, false, nil
	}
	return memClaim, memExists, nil
}
