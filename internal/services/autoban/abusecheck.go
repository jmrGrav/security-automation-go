package autoban

import (
	"context"
	"net/netip"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment"
)

// AbuseIPDBChecker is the minimal AbuseIPDB transport interface needed by AutoBan.
type AbuseIPDBChecker interface {
	// CheckScore calls AbuseIPDB /check and returns the abuseConfidenceScore for ip,
	// or -1 on error (caller should fail-open).
	CheckScore(ctx context.Context, ip string) (int, error)
}

// cachedEnricher adapts an AbuseIPDBChecker to the IPEnricher interface with
// an in-memory TTL cache. It prevents quota exhaustion on the AbuseIPDB Check API.
type cachedEnricher struct {
	checker AbuseIPDBChecker
	mu      sync.Mutex
	cache   map[string]cacheEntry
	ttl     time.Duration
	now     func() time.Time
}

type cacheEntry struct {
	score     int
	expiresAt time.Time
}

// NewCachedEnricher wraps checker with a TTL cache. Use 6h to match the enrichment
// service cache TTL and stay within AbuseIPDB's daily budget even at high event rates.
func NewCachedEnricher(checker AbuseIPDBChecker, ttl time.Duration) IPEnricher {
	return &cachedEnricher{
		checker: checker,
		cache:   make(map[string]cacheEntry),
		ttl:     ttl,
		now:     time.Now,
	}
}

func (c *cachedEnricher) Enrich(ctx context.Context, ip netip.Addr, _ enrichment.LookupOptions) (enrichment.EnrichmentSummary, error) {
	ipStr := ip.String()

	c.mu.Lock()
	if e, ok := c.cache[ipStr]; ok && c.now().Before(e.expiresAt) {
		c.mu.Unlock()
		return makeSummary(ip, e.score), nil
	}
	c.mu.Unlock()

	score, err := c.checker.CheckScore(ctx, ipStr)
	if err != nil {
		// Fail-open: return a zero score so the evaluator skips the ban.
		return enrichment.EnrichmentSummary{IP: ip}, err
	}

	c.mu.Lock()
	c.cache[ipStr] = cacheEntry{score: score, expiresAt: c.now().Add(c.ttl)}
	c.mu.Unlock()

	return makeSummary(ip, score), nil
}

func makeSummary(ip netip.Addr, score int) enrichment.EnrichmentSummary {
	return enrichment.EnrichmentSummary{
		IP: ip,
		Providers: []enrichment.ProviderVerdict{
			{Provider: "abuseipdb", Score: score, Manual: true},
		},
	}
}
