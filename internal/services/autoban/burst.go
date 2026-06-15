package autoban

import (
	"sort"
	"sync"
	"time"
)

// burstPruneLookback is the maximum age of events considered for burst detection.
// Must be longer than cloudflareReplayOverlap (10min) to cover all replayed events.
const burstPruneLookback = 15 * time.Minute

// BurstCounter tracks malicious event timestamps per IP using an in-memory
// sliding-window structure. All methods are safe for concurrent use.
type BurstCounter struct {
	mu     sync.Mutex
	events map[string][]time.Time
	seen   map[string]struct{} // dedup: "ip:rayID"
}

func NewBurstCounter() *BurstCounter {
	return &BurstCounter{
		events: make(map[string][]time.Time),
		seen:   make(map[string]struct{}),
	}
}

// Record adds a malicious event for ip at time ts. key is a unique event
// identifier (ray_id) used to prevent double-counting from replay overlap.
// When key is empty, every call is recorded (no dedup).
func (c *BurstCounter) Record(ip, key string, ts time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if key != "" {
		dk := ip + ":" + key
		if _, ok := c.seen[dk]; ok {
			return
		}
		c.seen[dk] = struct{}{}
	}
	c.events[ip] = append(c.events[ip], ts)
}

// HasLocalEvidence returns true if at least one event for ip has been recorded
// within burstPruneLookback before now. Used to require local corroboration
// before acting on an external reputation score.
func (c *BurstCounter) HasLocalEvidence(ip string, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	cutoff := now.Add(-burstPruneLookback)
	for _, t := range c.events[ip] {
		if t.After(cutoff) {
			return true
		}
	}
	return false
}

// DetectBurst returns true if there exists any window-duration sub-window within
// the stored event timestamps for ip that contains more than threshold events.
//
// It operates on event timestamps, not wall clock, so it correctly identifies
// historical bursts replayed up to burstPruneLookback before now. Events older
// than burstPruneLookback are pruned in place.
func (c *BurstCounter) DetectBurst(ip string, window time.Duration, threshold int, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	cutoff := now.Add(-burstPruneLookback)
	raw := c.events[ip]
	var ts []time.Time
	for _, t := range raw {
		if t.After(cutoff) {
			ts = append(ts, t)
		}
	}
	c.events[ip] = ts

	if len(ts) <= threshold {
		return false
	}
	sort.Slice(ts, func(i, j int) bool { return ts[i].Before(ts[j]) })
	for i := range ts {
		count := 1
		end := ts[i].Add(window)
		for j := i + 1; j < len(ts); j++ {
			if !ts[j].Before(end) {
				break
			}
			count++
			if count > threshold {
				return true
			}
		}
	}
	return false
}
