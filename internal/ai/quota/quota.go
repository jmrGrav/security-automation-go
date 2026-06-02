package quota

import (
	"strings"
	"sync"
	"time"
)

// State represents the operational posture of an AI provider quota.
type State string

const (
	Normal    State = "NORMAL"
	Warning   State = "WARNING"
	Throttled State = "THROTTLED"
	Exhausted State = "EXHAUSTED"
	Cooldown  State = "COOLDOWN"
	Unknown   State = "UNKNOWN"
	Disabled  State = "DISABLED"
)

// ProviderQuota describes the read-only observed quota posture for a provider.
type ProviderQuota struct {
	Provider       string
	State          State
	RequestsLimit  int
	RequestsUsed   int
	RequestsRemain int
	TokensLimit    int
	TokensUsed     int
	TokensRemain   int
	ResetAt        *time.Time
	ResetKnown     bool
	RetryAfter     *time.Duration
	LastObservedAt time.Time
	Source         string
}

// Registry is the future quota observation store for AI providers.
type Registry interface {
	Get(provider string) (ProviderQuota, bool)
	Set(quota ProviderQuota)
	Snapshot() []ProviderQuota
}

// CanUse reports whether a provider quota posture is eligible for a read-only call.
func CanUse(q ProviderQuota) bool {
	return CanUseAt(q, time.Now().UTC())
}

// CanUseAt reports whether a provider quota posture is eligible at a specific time.
func CanUseAt(q ProviderQuota, now time.Time) bool {
	switch q.State {
	case Disabled:
		return false
	case Exhausted, Cooldown:
		resetAt, ok := resetTime(q)
		if !ok {
			return false
		}
		return !now.Before(resetAt)
	default:
		return true
	}
}

// Better reports whether a is preferable to b for fallback ordering.
func Better(a, b ProviderQuota) bool {
	priority := func(q ProviderQuota) int {
		switch q.State {
		case Normal:
			return 5
		case Warning:
			return 4
		case Throttled:
			return 3
		case Unknown:
			return 2
		default:
			return 1
		}
	}
	if pa, pb := priority(a), priority(b); pa != pb {
		return pa > pb
	}
	if a.TokensRemain != b.TokensRemain {
		return a.TokensRemain > b.TokensRemain
	}
	return a.RequestsRemain > b.RequestsRemain
}

func (q ProviderQuota) clone() ProviderQuota {
	out := q
	if q.ResetAt != nil {
		reset := *q.ResetAt
		out.ResetAt = &reset
	}
	if q.RetryAfter != nil {
		retry := *q.RetryAfter
		out.RetryAfter = &retry
	}
	return out
}

func resetTime(q ProviderQuota) (time.Time, bool) {
	if q.ResetAt != nil {
		return q.ResetAt.UTC(), true
	}
	if q.RetryAfter != nil && !q.LastObservedAt.IsZero() {
		return q.LastObservedAt.Add(*q.RetryAfter).UTC(), true
	}
	return time.Time{}, false
}

// MemoryRegistry is a thread-safe in-memory registry for AI provider quota state.
type MemoryRegistry struct {
	mu    sync.RWMutex
	items map[string]ProviderQuota
}

// NewMemoryRegistry constructs an empty registry.
func NewMemoryRegistry() *MemoryRegistry {
	return &MemoryRegistry{items: make(map[string]ProviderQuota)}
}

func normalizeProvider(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

// Set records the latest observed quota state for a provider.
func (r *MemoryRegistry) Set(quota ProviderQuota) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.items == nil {
		r.items = make(map[string]ProviderQuota)
	}
	r.items[normalizeProvider(quota.Provider)] = quota
}

// Get returns the current quota state for a provider.
func (r *MemoryRegistry) Get(provider string) (ProviderQuota, bool) {
	if r == nil {
		return ProviderQuota{}, false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	quota, ok := r.items[normalizeProvider(provider)]
	if !ok {
		return ProviderQuota{}, false
	}
	return quota, true
}

// Snapshot returns all observed quota states.
func (r *MemoryRegistry) Snapshot() []ProviderQuota {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ProviderQuota, 0, len(r.items))
	for _, quota := range r.items {
		out = append(out, quota)
	}
	return out
}
