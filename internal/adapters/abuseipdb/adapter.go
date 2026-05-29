// Package abuseipdb provides a provider-specific reputation lookup adapter.
// It owns HTTP translation, caching, and serialization, but leaves policy
// decisions to outer layers.
package abuseipdb

import (
	"context"
	"fmt"
	"net/netip"
	"sync"
	"time"

	abusemodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	abtransport "github.com/jm/security-automation-go/internal/abuseipdb/transport"
	"github.com/jm/security-automation-go/internal/security/reputation"
)

type Config struct {
	TTL     time.Duration
	Timeout time.Duration
}

type cacheEntry struct {
	expiresAt time.Time
	response  abusemodels.CheckResponse
}

type Checker struct {
	transport *abtransport.Transport
	cfg       Config

	mu    sync.RWMutex
	cache map[string]cacheEntry
}

func NewChecker(transport *abtransport.Transport, cfg Config) *Checker {
	if cfg.TTL <= 0 {
		cfg.TTL = 15 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	return &Checker{
		transport: transport,
		cfg:       cfg,
		cache:     make(map[string]cacheEntry),
	}
}

func (c *Checker) Check(ctx context.Context, ip netip.Addr) (reputation.Result, error) {
	if !ip.IsValid() {
		return reputation.Result{}, fmt.Errorf("abuseipdb checker: ip is required")
	}

	resp, cacheHit, err := c.lookup(ctx, ip.String())
	if err != nil {
		return reputation.Result{}, err
	}

	return reputation.Result{
		IP:        ip,
		Provider:  "abuseipdb",
		Score:     resp.Data.AbuseConfidenceScore,
		CheckedAt: time.Now().UTC(),
		CacheHit:  cacheHit,
	}, nil
}

func (c *Checker) lookup(ctx context.Context, ip string) (*abusemodels.CheckResponse, bool, error) {
	now := time.Now().UTC()
	c.mu.RLock()
	entry, ok := c.cache[ip]
	c.mu.RUnlock()
	if ok && now.Before(entry.expiresAt) {
		return &entry.response, true, nil
	}

	timeoutCtx, cancel := context.WithTimeout(ctx, c.cfg.Timeout)
	defer cancel()

	resp, err := c.transport.Check(timeoutCtx, ip)
	if err != nil {
		return nil, false, err
	}

	c.mu.Lock()
	c.cache[ip] = cacheEntry{
		expiresAt: now.Add(c.cfg.TTL),
		response:  *resp,
	}
	c.mu.Unlock()

	return resp, false, nil
}
