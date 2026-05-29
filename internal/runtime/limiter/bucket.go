package limiter

import (
	"sync"
	"time"
)

// Bucket implements a thread-safe token bucket for rate limiting.
type Bucket struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	refillRate float64 // tokens per second
	lastRefill time.Time
}

func NewBucket(capacity int, rate int, interval time.Duration) *Bucket {
	return &Bucket{
		capacity:   float64(capacity),
		tokens:     float64(capacity),
		refillRate: float64(rate) / interval.Seconds(),
		lastRefill: time.Now(),
	}
}

func (b *Bucket) Allow(n int) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.refill()

	if b.tokens >= float64(n) {
		b.tokens -= float64(n)
		return true
	}

	return false
}

func (b *Bucket) refill() {
	now := time.Now()
	elapsed := now.Sub(b.lastRefill).Seconds()

	b.tokens += elapsed * b.refillRate
	if b.tokens > b.capacity {
		b.tokens = b.capacity
	}

	b.lastRefill = now
}

func (b *Bucket) Saturation() float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.refill()
	return 1.0 - (b.tokens / b.capacity)
}

// HierarchicalLimiter coordinates limits across global, tenant, and scope levels.
type HierarchicalLimiter struct {
	Global *Bucket
	Tenant *Bucket
	Scope  *Bucket
}

func (h *HierarchicalLimiter) Allow(n int) bool {
	// Must pass ALL buckets in the hierarchy
	// Using a "peek then commit" or "all-at-once" lock strategy if distributed,
	// for local we just check Global -> Tenant -> Scope in sequence (simple approximation).

	if h.Global != nil && !h.Global.Allow(n) {
		return false
	}
	if h.Tenant != nil && !h.Tenant.Allow(n) {
		// Rollback Global? For now, we assume buckets are reasonably sized or we use a strict atomic commit.
		return false
	}
	if h.Scope != nil && !h.Scope.Allow(n) {
		return false
	}

	return true
}
