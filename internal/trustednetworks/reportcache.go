package trustednetworks

import "sync"

// ReportCache holds the most recent SyncReport so a read-only consumer (the
// UI) can display live sync status without re-running Sync itself. It is
// safe to share a single *ReportCache between the goroutine that runs Sync
// and any number of readers.
type ReportCache struct {
	mu   sync.RWMutex
	last SyncReport
	set  bool
}

// NewReportCache returns an empty cache; Get reports ok=false until the
// first Set.
func NewReportCache() *ReportCache {
	return &ReportCache{}
}

// Set records the most recent SyncReport. Safe to call from the sync loop's
// goroutine concurrently with Get calls from request-handling goroutines.
func (c *ReportCache) Set(report SyncReport) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last = report
	c.set = true
}

// Get returns the most recently cached SyncReport. ok is false if Sync has
// never completed (e.g. feature disabled, or daemon hasn't run its first
// pass yet) — callers must treat that as "unknown", never as "synced".
func (c *ReportCache) Get() (SyncReport, bool) {
	if c == nil {
		return SyncReport{}, false
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.last, c.set
}
