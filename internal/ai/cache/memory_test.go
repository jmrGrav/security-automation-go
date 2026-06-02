package cache

import (
	"context"
	"testing"
	"time"
)

func TestMemoryStorePrunesExpiredEntriesAndCapsSize(t *testing.T) {
	store := NewMemoryStoreWithCapacity(2)
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }
	store.cleanupEvery = 1

	if err := store.Put(context.Background(), Entry{Key: "expired", Explanation: "old", ExpiresAt: base.Add(-time.Minute)}); err != nil {
		t.Fatalf("put expired: %v", err)
	}
	if err := store.Put(context.Background(), Entry{Key: "first", Explanation: "first", ExpiresAt: base.Add(time.Hour)}); err != nil {
		t.Fatalf("put first: %v", err)
	}
	if err := store.Put(context.Background(), Entry{Key: "second", Explanation: "second", ExpiresAt: base.Add(time.Hour)}); err != nil {
		t.Fatalf("put second: %v", err)
	}

	if got := len(store.items); got != 2 {
		t.Fatalf("expected cache to stay bounded at 2 entries, got %d", got)
	}
	if _, ok := store.Get(context.Background(), "expired"); ok {
		t.Fatal("expired entry should have been pruned")
	}
	if _, ok := store.Get(context.Background(), "first"); !ok {
		t.Fatal("expected first entry to remain after pruning")
	}
	if _, ok := store.Get(context.Background(), "second"); !ok {
		t.Fatal("expected second entry to remain after pruning")
	}
}
