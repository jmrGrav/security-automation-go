package reporting

import (
	"sync"
	"time"
)

// spamhausIPDedup provides in-memory per-IP deduplication for Spamhaus Submit.
// It prevents re-submission of the same IP within the configured TTL (default 24h).
// State is not persisted; it resets on restart, which is acceptable given
// Spamhaus's own server-side dedup and the low volume of confident events.
type spamhausIPDedup struct {
	mu   sync.Mutex
	seen map[string]time.Time
	ttl  time.Duration
	now  func() time.Time
}

func newSpamhausIPDedup(ttl time.Duration, now func() time.Time) *spamhausIPDedup {
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &spamhausIPDedup{
		seen: make(map[string]time.Time),
		ttl:  ttl,
		now:  now,
	}
}

func (d *spamhausIPDedup) setClock(now func() time.Time) {
	if d != nil && now != nil {
		d.mu.Lock()
		d.now = now
		d.mu.Unlock()
	}
}

// markSeen records ip as submitted and returns true if it was already seen within TTL.
func (d *spamhausIPDedup) markSeen(ip string) bool {
	if d == nil {
		return false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	now := d.now()
	for k, exp := range d.seen {
		if now.After(exp) {
			delete(d.seen, k)
		}
	}
	if exp, ok := d.seen[ip]; ok && now.Before(exp) {
		return true
	}
	d.seen[ip] = now.Add(d.ttl)
	return false
}
