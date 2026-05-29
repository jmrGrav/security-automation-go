package sqlite

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/ownership"
)

func TestOwnershipLineageAppendAndList(t *testing.T) {
	t.Parallel()

	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	repo := NewOwnershipRepository(db)
	now := time.Date(2026, 5, 29, 0, 0, 0, 0, time.UTC)
	ev1 := ownership.LineageEvent{
		ID:           "ev-1",
		ScopeID:      "scope-a",
		ResourceID:   "res-1",
		DomainID:     "cf-sync",
		EventType:    ownership.LineageEventClaim,
		Decision:     "claim_set",
		Epoch:        1,
		DecisionHash: "hash-1",
		CreatedAt:    now,
	}
	ev2 := ownership.LineageEvent{
		ID:            "ev-2",
		ParentID:      "ev-1",
		ScopeID:       "scope-a",
		ResourceID:    "res-1",
		DomainID:      "cf-sync",
		EventType:     ownership.LineageEventResolve,
		Decision:      "allow",
		RequiredRight: ownership.RightUpdate,
		Epoch:         1,
		DecisionHash:  "hash-2",
		CreatedAt:     now.Add(time.Second),
	}

	if err := repo.AppendLineage(context.Background(), ev1); err != nil {
		t.Fatalf("append ev1: %v", err)
	}
	if err := repo.AppendLineage(context.Background(), ev2); err != nil {
		t.Fatalf("append ev2: %v", err)
	}

	got, err := repo.ListLineage(context.Background(), "scope-a", "res-1", 10)
	if err != nil {
		t.Fatalf("list lineage: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 lineage events, got %d", len(got))
	}
	if got[0].ID != "ev-2" || got[1].ID != "ev-1" {
		t.Fatalf("unexpected lineage order: %+v", got)
	}

	item, found, err := repo.GetLineage(context.Background(), "ev-1")
	if err != nil {
		t.Fatalf("get lineage: %v", err)
	}
	if !found || item.ID != "ev-1" {
		t.Fatalf("expected ev-1 from get lineage, got found=%v item=%+v", found, item)
	}
}

func TestOwnershipLineageReplayMatchesLatestClaim(t *testing.T) {
	t.Parallel()

	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	repo := NewOwnershipRepository(db)
	now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
	claim1 := ownership.OwnershipClaim{
		ScopeID:    "scope-a",
		ResourceID: "res-1",
		DomainID:   "cf-sync",
		Epoch:      1,
		Rights:     []ownership.Right{ownership.RightUpdate},
		Timestamp:  now,
	}
	claim2 := ownership.OwnershipClaim{
		ScopeID:    "scope-a",
		ResourceID: "res-1",
		DomainID:   "terraform",
		Epoch:      2,
		Rights:     []ownership.Right{ownership.RightUpdate, ownership.RightOverride},
		Timestamp:  now.Add(time.Second),
	}
	if err := repo.SetClaim(context.Background(), claim1); err != nil {
		t.Fatalf("set claim1: %v", err)
	}
	if err := repo.AppendLineage(context.Background(), ownership.LineageEvent{
		ID:           "l1",
		ScopeID:      "scope-a",
		ResourceID:   "res-1",
		DomainID:     "cf-sync",
		EventType:    ownership.LineageEventClaim,
		Epoch:        1,
		DecisionHash: "h1",
		CreatedAt:    now,
	}); err != nil {
		t.Fatalf("append lineage l1: %v", err)
	}
	if err := repo.SetClaim(context.Background(), claim2); err != nil {
		t.Fatalf("set claim2: %v", err)
	}
	if err := repo.AppendLineage(context.Background(), ownership.LineageEvent{
		ID:           "l2",
		ScopeID:      "scope-a",
		ResourceID:   "res-1",
		DomainID:     "terraform",
		EventType:    ownership.LineageEventClaim,
		Epoch:        2,
		DecisionHash: "h2",
		CreatedAt:    now.Add(time.Second),
	}); err != nil {
		t.Fatalf("append lineage l2: %v", err)
	}

	lineage, err := repo.ListLineage(context.Background(), "scope-a", "res-1", 100)
	if err != nil {
		t.Fatalf("list lineage: %v", err)
	}
	rebuilt := ownership.RebuildClaimsFromLineage(lineage)
	got, ok := rebuilt["scope-a|res-1"]
	if !ok {
		t.Fatal("expected rebuilt claim for scope-a|res-1")
	}
	if got.DomainID != "terraform" || got.Epoch != 2 {
		t.Fatalf("unexpected rebuilt claim: %+v", got)
	}
}

func TestOwnershipLineageCursorPagination(t *testing.T) {
	t.Parallel()

	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	repo := NewOwnershipRepository(db)
	base := time.Date(2026, 5, 29, 15, 0, 0, 0, time.UTC)
	events := []ownership.LineageEvent{
		{ID: "c3", ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync", EventType: ownership.LineageEventClaim, Epoch: 3, DecisionHash: "h3", CreatedAt: base.Add(2 * time.Second)},
		{ID: "c2", ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync", EventType: ownership.LineageEventClaim, Epoch: 2, DecisionHash: "h2", CreatedAt: base.Add(1 * time.Second)},
		{ID: "c1", ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync", EventType: ownership.LineageEventClaim, Epoch: 1, DecisionHash: "h1", CreatedAt: base},
	}
	for _, ev := range events {
		if err := repo.AppendLineage(context.Background(), ev); err != nil {
			t.Fatalf("append lineage %s: %v", ev.ID, err)
		}
	}

	page1, err := repo.ListLineageCursor(context.Background(), "scope-a", "res-1", time.Time{}, "", 2)
	if err != nil {
		t.Fatalf("list page1: %v", err)
	}
	if len(page1) != 2 || page1[0].ID != "c3" || page1[1].ID != "c2" {
		t.Fatalf("unexpected page1: %+v", page1)
	}

	cursorCreatedAt := page1[len(page1)-1].CreatedAt
	cursorID := page1[len(page1)-1].ID
	page2, err := repo.ListLineageCursor(context.Background(), "scope-a", "res-1", cursorCreatedAt, cursorID, 2)
	if err != nil {
		t.Fatalf("list page2: %v", err)
	}
	if len(page2) != 1 || page2[0].ID != "c1" {
		t.Fatalf("unexpected page2: %+v", page2)
	}
}

func TestOwnershipLineageCursorPaginationConcurrentAppendNoDuplicateOlderSlice(t *testing.T) {
	t.Parallel()

	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	repo := NewOwnershipRepository(db)

	base := time.Date(2026, 5, 29, 16, 0, 0, 0, time.UTC)
	initial := []ownership.LineageEvent{
		{ID: "p3", ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync", EventType: ownership.LineageEventClaim, Epoch: 3, DecisionHash: "h3", CreatedAt: base.Add(3 * time.Second)},
		{ID: "p2", ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync", EventType: ownership.LineageEventClaim, Epoch: 2, DecisionHash: "h2", CreatedAt: base.Add(2 * time.Second)},
		{ID: "p1", ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync", EventType: ownership.LineageEventClaim, Epoch: 1, DecisionHash: "h1", CreatedAt: base.Add(1 * time.Second)},
	}
	for _, ev := range initial {
		if err := repo.AppendLineage(context.Background(), ev); err != nil {
			t.Fatalf("append initial %s: %v", ev.ID, err)
		}
	}

	page1, err := repo.ListLineageCursor(context.Background(), "scope-a", "res-1", time.Time{}, "", 2)
	if err != nil {
		t.Fatalf("page1: %v", err)
	}
	if len(page1) != 2 {
		t.Fatalf("expected page1 len=2, got %d", len(page1))
	}
	cursorAt := page1[len(page1)-1].CreatedAt
	cursorID := page1[len(page1)-1].ID

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		// Append a newer event after first page fetch: must not corrupt old-slice pagination.
		_ = repo.AppendLineage(context.Background(), ownership.LineageEvent{
			ID:      "p4-new",
			ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync",
			EventType: ownership.LineageEventClaim, Epoch: 4, DecisionHash: "h4", CreatedAt: base.Add(4 * time.Second),
		})
	}()
	wg.Wait()

	page2, err := repo.ListLineageCursor(context.Background(), "scope-a", "res-1", cursorAt, cursorID, 5)
	if err != nil {
		t.Fatalf("page2: %v", err)
	}
	for _, ev := range page2 {
		if ev.ID == "p4-new" {
			t.Fatalf("newer concurrent append must not appear in older cursor slice: %+v", page2)
		}
		if ev.ID == page1[0].ID || ev.ID == page1[1].ID {
			t.Fatalf("duplicate across pages detected: page1=%+v page2=%+v", page1, page2)
		}
	}
}
