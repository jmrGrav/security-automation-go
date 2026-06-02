package cache

import (
	"context"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/observability/metrics"
)

// MemoryStore is a small TTL cache for AI explanations.
type MemoryStore struct {
	mu           sync.RWMutex
	items        map[string]Entry
	now          func() time.Time
	maxEntries   int
	cleanupEvery int
	puts         int
	lastSweep    time.Time
}

// NewMemoryStore constructs an empty TTL cache.
func NewMemoryStore() *MemoryStore {
	return NewMemoryStoreWithCapacity(2048)
}

func NewMemoryStoreWithCapacity(maxEntries int) *MemoryStore {
	if maxEntries <= 0 {
		maxEntries = 2048
	}
	return &MemoryStore{
		items:        make(map[string]Entry),
		now:          time.Now,
		maxEntries:   maxEntries,
		cleanupEvery: 32,
	}
}

// Get returns a cached entry if it exists and has not expired.
func (s *MemoryStore) Get(ctx context.Context, key string) (Entry, bool) {
	if s == nil {
		return Entry{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.maybeSweepLocked()
	entry, ok := s.items[key]
	if !ok {
		return Entry{}, false
	}
	if !entry.ExpiresAt.IsZero() && s.now().After(entry.ExpiresAt) {
		delete(s.items, key)
		metrics.AIExplainCachePrunedTotal.Inc()
		metrics.AIExplainCacheEntries.Set(float64(len(s.items)))
		return Entry{}, false
	}
	return entry, true
}

// Put stores an entry in the cache.
func (s *MemoryStore) Put(ctx context.Context, entry Entry) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.items == nil {
		s.items = make(map[string]Entry)
	}
	s.puts++
	s.maybeSweepLocked()
	if len(s.items) >= s.maxEntries {
		s.evictOldestLocked()
	}
	s.items[entry.Key] = entry
	metrics.AIExplainCacheEntries.Set(float64(len(s.items)))
	return nil
}

func (s *MemoryStore) maybeSweepLocked() {
	if s == nil {
		return
	}
	now := s.now()
	if s.cleanupEvery > 0 && s.puts%s.cleanupEvery != 0 {
		if !s.lastSweep.IsZero() && now.Sub(s.lastSweep) < 5*time.Minute {
			return
		}
	}
	removed := s.sweepExpiredLocked(now)
	if removed > 0 {
		metrics.AIExplainCachePrunedTotal.Add(float64(removed))
	}
	s.lastSweep = now
	metrics.AIExplainCacheEntries.Set(float64(len(s.items)))
}

func (s *MemoryStore) sweepExpiredLocked(now time.Time) int {
	removed := 0
	for key, entry := range s.items {
		if !entry.ExpiresAt.IsZero() && now.After(entry.ExpiresAt) {
			delete(s.items, key)
			removed++
		}
	}
	return removed
}

func (s *MemoryStore) evictOldestLocked() {
	if len(s.items) == 0 {
		return
	}
	var (
		oldestKey  string
		oldest     Entry
		haveOldest bool
	)
	for key, entry := range s.items {
		if !haveOldest {
			oldestKey = key
			oldest = entry
			haveOldest = true
			continue
		}
		if entry.ExpiresAt.IsZero() {
			if oldest.ExpiresAt.IsZero() {
				if key < oldestKey {
					oldestKey = key
					oldest = entry
				}
				continue
			}
			oldestKey = key
			oldest = entry
			continue
		}
		if oldest.ExpiresAt.IsZero() || entry.ExpiresAt.Before(oldest.ExpiresAt) {
			oldestKey = key
			oldest = entry
			continue
		}
		if entry.ExpiresAt.Equal(oldest.ExpiresAt) && key < oldestKey {
			oldestKey = key
			oldest = entry
		}
	}
	if oldestKey != "" {
		delete(s.items, oldestKey)
		metrics.AIExplainCachePrunedTotal.Inc()
	}
}
