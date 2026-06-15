package autoban

import (
	"sync"
	"time"
)

// BanDedup prevents the same IP from being banned repeatedly within a TTL window.
// It is in-memory — a process restart resets it, which is acceptable since CF bans
// are persistent. The dedup only prevents thrashing within a single process lifetime.
type BanDedup struct {
	mu   sync.Mutex
	bans map[string]time.Time
	ttl  time.Duration
}

func NewBanDedup(ttl time.Duration) *BanDedup {
	return &BanDedup{bans: make(map[string]time.Time), ttl: ttl}
}

// AlreadyBanned returns true if ip was banned within the TTL window.
func (d *BanDedup) AlreadyBanned(ip string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	t, ok := d.bans[ip]
	if !ok {
		return false
	}
	return now.Before(t.Add(d.ttl))
}

// MarkBanned records a ban for ip at now.
func (d *BanDedup) MarkBanned(ip string, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bans[ip] = now
}
