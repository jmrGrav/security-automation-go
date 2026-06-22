package autoban

import (
	"sync"
	"time"
)

// banRecord tracks when an IP was last banned and for how long that specific
// ban's dedup guard should hold, so the guard tracks the REAL applied ban
// duration instead of one fixed TTL for every tier.
type banRecord struct {
	at  time.Time
	ttl time.Duration
}

// BanDedup prevents the same IP from being banned repeatedly while its most
// recently recorded ban's dedup window is still open. It is in-memory — a
// process restart resets it, which is acceptable since CF bans are
// persistent. The dedup only prevents thrashing within a single process
// lifetime.
//
// Each ban is recorded with its own TTL (see MarkBanned), reflecting the
// actual duration applied to that specific ban (e.g. a 1h first-tier ban
// vs. a 24h third-tier ban) rather than one fixed window for every tier.
// defaultTTL is used only as a fallback by the legacy fixed-TTL call path
// (Evaluator.RecordBan) for callers that don't know a specific duration.
type BanDedup struct {
	mu         sync.Mutex
	bans       map[string]banRecord
	defaultTTL time.Duration
}

// NewBanDedup constructs a BanDedup. defaultTTL is used by MarkBanned when no
// specific per-ban TTL is known (the legacy fixed-window fallback).
func NewBanDedup(defaultTTL time.Duration) *BanDedup {
	return &BanDedup{bans: make(map[string]banRecord), defaultTTL: defaultTTL}
}

// AlreadyBanned returns true if ip was banned within its recorded ban's TTL
// window. Each IP's window reflects the TTL passed to its most recent
// MarkBanned call, not a single fixed duration shared by every IP.
func (d *BanDedup) AlreadyBanned(ip string, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.bans[ip]
	if !ok {
		return false
	}
	return now.Before(r.at.Add(r.ttl))
}

// MarkBanned records a ban for ip at now with the given ttl — the dedup
// guard for this IP will hold AlreadyBanned true until now+ttl elapses. Pass
// the actual duration that was applied to the real ban (e.g. the value
// returned by banlifecycle.DurationPolicy.DurationFor) whenever it is known,
// so the in-memory guard never outlives — or, just as importantly, never
// falls short of — the real Cloudflare ban it is standing in for.
func (d *BanDedup) MarkBanned(ip string, now time.Time, ttl time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.bans[ip] = banRecord{at: now, ttl: ttl}
}

// MarkBannedDefaultTTL records a ban for ip using the dedup's configured
// defaultTTL. Used by call sites that genuinely have no specific duration to
// report (the legacy fixed-window behaviour).
func (d *BanDedup) MarkBannedDefaultTTL(ip string, now time.Time) {
	d.MarkBanned(ip, now, d.defaultTTL)
}
