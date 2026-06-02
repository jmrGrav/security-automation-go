package enrichment

import (
	"sync"
	"time"
)

type cacheEntry struct {
	expiresAt time.Time
	summary   EnrichmentSummary
}

type summaryCache struct {
	mu    sync.RWMutex
	items map[string]cacheEntry
	ttl   time.Duration
}

func newSummaryCache(ttl time.Duration) *summaryCache {
	if ttl <= 0 {
		ttl = time.Minute
	}
	return &summaryCache{
		items: make(map[string]cacheEntry),
		ttl:   ttl,
	}
}

func (c *summaryCache) Get(key string) (EnrichmentSummary, bool) {
	now := time.Now().UTC()
	c.mu.RLock()
	entry, ok := c.items[key]
	c.mu.RUnlock()
	if !ok || now.After(entry.expiresAt) {
		if ok {
			c.mu.Lock()
			delete(c.items, key)
			c.mu.Unlock()
		}
		return EnrichmentSummary{}, false
	}
	return entry.summary, true
}

func (c *summaryCache) Put(key string, summary EnrichmentSummary) {
	c.mu.Lock()
	c.items[key] = cacheEntry{
		expiresAt: time.Now().UTC().Add(c.ttl),
		summary:   summary,
	}
	c.mu.Unlock()
}
