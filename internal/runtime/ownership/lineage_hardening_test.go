package ownership_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/ownership"
)

type lineageMemoryStore struct {
	byID      map[string]ownership.LineageEvent
	events    []ownership.LineageEvent
	listErr   error
	getErr    error
	cursorErr error
}

func (s *lineageMemoryStore) GetLineage(_ context.Context, eventID string) (ownership.LineageEvent, bool, error) {
	if s.getErr != nil {
		return ownership.LineageEvent{}, false, s.getErr
	}
	ev, ok := s.byID[eventID]
	return ev, ok, nil
}

func (s *lineageMemoryStore) ListLineage(_ context.Context, scopeID string, resourceID string, limit int) ([]ownership.LineageEvent, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]ownership.LineageEvent, 0)
	for _, ev := range s.events {
		if ev.ScopeID == scopeID && ev.ResourceID == resourceID {
			out = append(out, ev)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *lineageMemoryStore) ListLineageCursor(_ context.Context, scopeID string, resourceID string, beforeCreatedAt time.Time, beforeID string, limit int) ([]ownership.LineageEvent, error) {
	if s.cursorErr != nil {
		return nil, s.cursorErr
	}
	var out []ownership.LineageEvent
	for _, ev := range s.events {
		if ev.ScopeID != scopeID || ev.ResourceID != resourceID {
			continue
		}
		if !beforeCreatedAt.IsZero() {
			if ev.CreatedAt.After(beforeCreatedAt) || (ev.CreatedAt.Equal(beforeCreatedAt) && beforeID != "" && ev.ID >= beforeID) {
				continue
			}
		}
		out = append(out, ev)
	}
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func TestDecisionHashAndLineageEventIDAreDeterministicAndScoped(t *testing.T) {
	t.Parallel()

	hash1 := ownership.BuildDecisionHash(ownership.LineageEventClaim, "scope-a", "res-1", "domain-a", "allow", "reason", ownership.RightUpdate, "owner-a", 7)
	hash2 := ownership.BuildDecisionHash(ownership.LineageEventClaim, "scope-a", "res-1", "domain-a", "allow", "reason", ownership.RightUpdate, "owner-a", 7)
	if hash1 != hash2 {
		t.Fatalf("decision hash must be stable, got %q and %q", hash1, hash2)
	}
	if other := ownership.BuildDecisionHash(ownership.LineageEventClaim, "scope-b", "res-1", "domain-a", "allow", "reason", ownership.RightUpdate, "owner-a", 7); other == hash1 {
		t.Fatal("decision hash must change when scope changes")
	}

	ts := time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)
	id1 := ownership.NewLineageEventID("scope-a", "res-1", ts)
	id2 := ownership.NewLineageEventID("scope-a", "res-1", ts)
	if id1 != id2 {
		t.Fatalf("lineage event id must be stable, got %q and %q", id1, id2)
	}
	if other := ownership.NewLineageEventID("scope-b", "res-1", ts); other == id1 {
		t.Fatal("lineage event id must change when scope changes")
	}
}

func TestLineageQueryServiceGetSearchAndExplain(t *testing.T) {
	t.Parallel()

	claim := ownership.LineageEvent{
		ID:           "lineage-1",
		ScopeID:      "scope-a",
		ResourceID:   "res-1",
		DomainID:     "domain-a",
		EventType:    ownership.LineageEventClaim,
		Decision:     "claim_set",
		DecisionHash: "hash-1",
		Epoch:        1,
		CreatedAt:    time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC),
	}
	resolve := ownership.LineageEvent{
		ID:           "lineage-2",
		ScopeID:      "scope-a",
		ResourceID:   "res-1",
		DomainID:     "domain-a",
		EventType:    ownership.LineageEventResolve,
		Decision:     "allow",
		DecisionHash: "hash-2",
		Epoch:        1,
		CreatedAt:    time.Date(2026, 6, 1, 11, 0, 0, 0, time.UTC),
	}
	store := &lineageMemoryStore{
		byID: map[string]ownership.LineageEvent{
			claim.ID: claim,
		},
		events: []ownership.LineageEvent{claim, resolve},
	}
	service := ownership.NewLineageQueryService(store)

	got, ok, err := service.Get(context.Background(), claim.ID)
	if err != nil || !ok {
		t.Fatalf("get: err=%v ok=%v", err, ok)
	}
	if got.ID != claim.ID {
		t.Fatalf("unexpected lineage event: %+v", got)
	}

	list, err := service.Search(context.Background(), ownership.LineageSearchOptions{
		ScopeID:    "scope-a",
		ResourceID: "res-1",
	})
	if err != nil {
		t.Fatalf("search: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected search to return both lineage events, got %+v", list)
	}

	claimExplanation := ownership.ExplainLineageEvent(claim)
	if claimExplanation.HumanReason != "ownership claim asserted" {
		t.Fatalf("unexpected claim explanation: %+v", claimExplanation)
	}
	resolveExplanation := ownership.ExplainLineageEvent(resolve)
	if resolveExplanation.HumanReason != "ownership resolution granted mutation rights" {
		t.Fatalf("unexpected resolve explanation: %+v", resolveExplanation)
	}
}

func TestLineageQueryServiceHandlesUnavailableStore(t *testing.T) {
	t.Parallel()

	service := ownership.NewLineageQueryService(nil)
	if _, _, err := service.Get(context.Background(), "lineage-1"); err == nil {
		t.Fatal("expected unavailable store error from Get")
	}
	if _, err := service.Search(context.Background(), ownership.LineageSearchOptions{}); err == nil {
		t.Fatal("expected unavailable store error from Search")
	}
}

func TestLineageQueryServiceSearchPropagatesStoreError(t *testing.T) {
	t.Parallel()

	service := ownership.NewLineageQueryService(&lineageMemoryStore{cursorErr: errors.New("cursor down")})
	if _, err := service.Search(context.Background(), ownership.LineageSearchOptions{ScopeID: "scope-a"}); err == nil {
		t.Fatal("expected search store error")
	}
}
