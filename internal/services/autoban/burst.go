package autoban

import (
	"sync"
	"time"
)

// BurstCounter tracks malicious event timestamps per IP in an in-memory sliding window.
// All methods are safe for concurrent use.
type BurstCounter struct {
	mu     sync.Mutex
	events map[string][]time.Time
}

func NewBurstCounter() *BurstCounter {
	return &BurstCounter{events: make(map[string][]time.Time)}
}

// Record adds a malicious event timestamp for ip. Only call for events that
// are definitively malicious (not suppressed as benign, not protected_target).
func (c *BurstCounter) Record(ip string, ts time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.events[ip] = append(c.events[ip], ts)
}

// Count returns the number of malicious events for ip within window before now,
// and prunes stale entries.
func (c *BurstCounter) Count(ip string, window time.Duration, now time.Time) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-window)
	ts := c.events[ip]
	var fresh []time.Time
	for _, t := range ts {
		if t.After(cutoff) {
			fresh = append(fresh, t)
		}
	}
	c.events[ip] = fresh
	return len(fresh)
}

// Prune removes all entries older than window before now across all IPs.
func (c *BurstCounter) Prune(window time.Duration, now time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-window)
	for ip, ts := range c.events {
		var fresh []time.Time
		for _, t := range ts {
			if t.After(cutoff) {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			delete(c.events, ip)
		} else {
			c.events[ip] = fresh
		}
	}
}
