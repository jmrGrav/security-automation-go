package ownership

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeClaimStore struct {
	claims map[string]OwnershipClaim
	getErr error
	setErr error
}

func newFakeClaimStore() *fakeClaimStore {
	return &fakeClaimStore{claims: make(map[string]OwnershipClaim)}
}

func (s *fakeClaimStore) GetClaim(_ context.Context, resourceID string) (OwnershipClaim, error) {
	if s.getErr != nil {
		return OwnershipClaim{}, s.getErr
	}
	return s.claims[resourceID], nil
}

func (s *fakeClaimStore) SetClaim(_ context.Context, claim OwnershipClaim) error {
	if s.setErr != nil {
		return s.setErr
	}
	s.claims[claim.ResourceID] = claim
	return nil
}

func (s *fakeClaimStore) ListClaims(_ context.Context) ([]OwnershipClaim, error) {
	out := make([]OwnershipClaim, 0, len(s.claims))
	for _, c := range s.claims {
		out = append(out, c)
	}
	return out, nil
}

func TestResolverUsesClaimStoreAcrossRestart(t *testing.T) {
	store := newFakeClaimStore()
	r1 := NewResolver()
	r1.SetClaimStore(store)
	r1.RegisterDomain(OwnershipDomain{
		ID:           "cf-sync",
		Priority:     80,
		Trust:        TrustManaged,
		Capabilities: []Right{RightCreate, RightUpdate},
	})
	r1.RegisterDomain(OwnershipDomain{
		ID:           "terraform",
		Priority:     100,
		Trust:        TrustAuthoritative,
		Capabilities: []Right{RightCreate, RightUpdate, RightOverride},
	})
	err := r1.Claim(OwnershipClaim{
		ScopeID:    "scope-a",
		ResourceID: "res-1",
		DomainID:   "terraform",
		Epoch:      42,
		Rights:     []Right{RightCreate, RightUpdate},
		Timestamp:  time.Now().UTC(),
	})
	if err != nil {
		t.Fatalf("claim should persist: %v", err)
	}

	// Simulate restart with fresh in-memory resolver.
	r2 := NewResolver()
	r2.SetClaimStore(store)
	r2.RegisterDomain(OwnershipDomain{
		ID:           "cf-sync",
		Priority:     80,
		Trust:        TrustManaged,
		Capabilities: []Right{RightCreate, RightUpdate},
	})
	r2.RegisterDomain(OwnershipDomain{
		ID:           "terraform",
		Priority:     100,
		Trust:        TrustAuthoritative,
		Capabilities: []Right{RightCreate, RightUpdate, RightOverride},
	})

	outcome, err := r2.Resolve(context.Background(), "cf-sync", "res-1", RightUpdate)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if outcome.Allowed {
		t.Fatalf("expected deny after restart due to persisted higher-priority owner, got %+v", outcome)
	}
	if outcome.Owner != "terraform" {
		t.Fatalf("expected persisted owner terraform, got %+v", outcome)
	}
}

func TestResolverClaimFailsWhenStoreWriteFails(t *testing.T) {
	store := newFakeClaimStore()
	store.setErr = errors.New("store unavailable")
	r := NewResolver()
	r.SetClaimStore(store)
	err := r.Claim(OwnershipClaim{
		ScopeID:    "scope-a",
		ResourceID: "res-2",
		DomainID:   "cf-sync",
		Epoch:      1,
	})
	if err == nil {
		t.Fatal("expected claim persistence failure")
	}
	if _, ok := store.claims["res-2"]; ok {
		t.Fatal("claim should not be persisted on store error")
	}
}

func TestResolverStoreAuthorityOverridesInMemoryDrift(t *testing.T) {
	store := newFakeClaimStore()
	store.claims["res-3"] = OwnershipClaim{
		ScopeID:    "scope-a",
		ResourceID: "res-3",
		DomainID:   "terraform",
		Epoch:      9,
		Rights:     []Right{RightUpdate, RightOverride},
		Timestamp:  time.Now().UTC(),
	}

	r := NewResolver()
	r.SetClaimStore(store)
	r.RegisterDomain(OwnershipDomain{
		ID:           "cf-sync",
		Priority:     80,
		Trust:        TrustManaged,
		Capabilities: []Right{RightUpdate},
	})
	r.RegisterDomain(OwnershipDomain{
		ID:           "terraform",
		Priority:     100,
		Trust:        TrustAuthoritative,
		Capabilities: []Right{RightUpdate, RightOverride},
	})

	// Simulate accidental in-memory drift that would incorrectly allow cf-sync.
	r.claims["res-3"] = OwnershipClaim{
		ScopeID:    "scope-a",
		ResourceID: "res-3",
		DomainID:   "cf-sync",
		Epoch:      10,
		Rights:     []Right{RightUpdate},
	}

	outcome, err := r.Resolve(context.Background(), "cf-sync", "res-3", RightUpdate)
	if err != nil {
		t.Fatalf("resolve failed: %v", err)
	}
	if outcome.Allowed {
		t.Fatalf("expected deny because persistent store claims terraform ownership, got %+v", outcome)
	}
	if outcome.Owner != "terraform" {
		t.Fatalf("expected terraform owner from store authority, got %+v", outcome)
	}
}
