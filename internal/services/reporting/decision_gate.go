package reporting

import (
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/security/classifier"
)

type decisionGate struct {
	mu                 sync.Mutex
	recentFingerprints map[string]time.Time
	ipLocks            map[string]*decisionGateIPLock
	dedupTTL           time.Duration
	now                func() time.Time
}

type decisionGateIPLock struct {
	mu       sync.Mutex
	lastUsed time.Time
	locked   bool
}

func newDecisionGate(dedupTTL time.Duration, now func() time.Time) *decisionGate {
	if dedupTTL <= 0 {
		dedupTTL = 15 * time.Minute
	}
	if now == nil {
		now = func() time.Time { return time.Now().UTC() }
	}
	return &decisionGate{
		recentFingerprints: make(map[string]time.Time),
		ipLocks:            make(map[string]*decisionGateIPLock),
		dedupTTL:           dedupTTL,
		now:                now,
	}
}

func (g *decisionGate) setClock(now func() time.Time) {
	if g != nil && now != nil {
		g.now = now
	}
}

func (g *decisionGate) isDuplicate(req Request, cls classifier.Classification) bool {
	if g == nil {
		return false
	}
	key := fingerprint(req, cls)
	now := g.now()

	g.mu.Lock()
	defer g.mu.Unlock()
	for k, expires := range g.recentFingerprints {
		if now.After(expires) {
			delete(g.recentFingerprints, k)
		}
	}
	g.pruneIPLocksLocked(now)
	metrics.ReportingDecisionGateEntries.Set(float64(len(g.ipLocks)))
	if expires, ok := g.recentFingerprints[key]; ok && now.Before(expires) {
		return true
	}
	g.recentFingerprints[key] = now.Add(g.dedupTTL)
	return false
}

func (g *decisionGate) lockIP(ip string) func() {
	if g == nil || ip == "" {
		return func() {}
	}
	now := g.now()
	g.mu.Lock()
	g.pruneIPLocksLocked(now)
	lock, ok := g.ipLocks[ip]
	if !ok {
		lock = &decisionGateIPLock{}
		g.ipLocks[ip] = lock
	}
	lock.lastUsed = now
	lock.locked = true
	metrics.ReportingDecisionGateEntries.Set(float64(len(g.ipLocks)))
	g.mu.Unlock()
	lock.mu.Lock()
	return func() {
		lock.mu.Unlock()
		g.mu.Lock()
		lock.lastUsed = g.now()
		lock.locked = false
		metrics.ReportingDecisionGateEntries.Set(float64(len(g.ipLocks)))
		g.mu.Unlock()
	}
}

func (g *decisionGate) pruneIPLocksLocked(now time.Time) {
	if g == nil {
		return
	}
	for ip, lock := range g.ipLocks {
		if lock.locked {
			continue
		}
		if now.Sub(lock.lastUsed) > g.dedupTTL {
			delete(g.ipLocks, ip)
			metrics.ReportingDecisionGatePrunedTotal.Inc()
		}
	}
}
