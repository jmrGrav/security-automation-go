package ownership

import (
	"testing"
	"time"
)

func TestRebuildClaimsFromLineage_UsesLatestClaimPerScopeResource(t *testing.T) {
	t.Parallel()

	base := time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC)
	events := []LineageEvent{
		{
			ID:         "1",
			ScopeID:    "scope-a",
			ResourceID: "res-1",
			DomainID:   "cf-sync",
			EventType:  LineageEventClaim,
			Epoch:      1,
			CreatedAt:  base,
		},
		{
			ID:         "2",
			ScopeID:    "scope-a",
			ResourceID: "res-1",
			DomainID:   "dashboard",
			EventType:  LineageEventClaim,
			Epoch:      2,
			CreatedAt:  base.Add(time.Second),
		},
		{
			ID:         "3",
			ScopeID:    "scope-b",
			ResourceID: "res-1",
			DomainID:   "cf-sync",
			EventType:  LineageEventClaim,
			Epoch:      1,
			CreatedAt:  base.Add(2 * time.Second),
		},
		{
			ID:         "4",
			ScopeID:    "scope-a",
			ResourceID: "res-1",
			DomainID:   "cf-sync",
			EventType:  LineageEventResolve,
			CreatedAt:  base.Add(3 * time.Second),
		},
	}

	claims := RebuildClaimsFromLineage(events)
	if len(claims) != 2 {
		t.Fatalf("expected 2 reconstructed claims, got %d", len(claims))
	}
	if got := claims["scope-a|res-1"]; got.DomainID != "dashboard" || got.Epoch != 2 {
		t.Fatalf("unexpected scope-a claim: %+v", got)
	}
	if got := claims["scope-b|res-1"]; got.DomainID != "cf-sync" || got.Epoch != 1 {
		t.Fatalf("unexpected scope-b claim: %+v", got)
	}
}
