// Package memstore provides an in-memory fake implementing
// banlifecycle.Store, for use in tests of code that depends on the
// banlifecycle.Store interface without needing a real SQLite database.
package memstore

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
)

// Store is a thread-safe in-memory implementation of banlifecycle.Store.
// It keeps the full history of entries per IP (active + completed) so that
// RecidiveLevel can count prior bans.
type Store struct {
	mu sync.Mutex
	// history holds every Upsert'd/MarkStatus'd entry for an IP, in
	// insertion order. The last element is always considered "current".
	history map[string][]banlifecycle.Entry
}

// New returns an empty in-memory Store.
func New() *Store {
	return &Store{history: make(map[string][]banlifecycle.Entry)}
}

func cloneEntry(e banlifecycle.Entry) banlifecycle.Entry {
	return e
}

// Upsert inserts a new active entry, or updates the current entry for the
// IP if one is already active. Mirrors the SQLite store's "one active row
// per IP, full history otherwise" semantics.
func (s *Store) Upsert(_ context.Context, e banlifecycle.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.history[e.IP]
	if n := len(entries); n > 0 && entries[n-1].Status == banlifecycle.StatusActive {
		entries[n-1] = cloneEntry(e)
		s.history[e.IP] = entries
		return nil
	}
	s.history[e.IP] = append(entries, cloneEntry(e))
	return nil
}

// Get returns the most recent entry for ip, if any.
func (s *Store) Get(_ context.Context, ip string) (banlifecycle.Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.history[ip]
	if len(entries) == 0 {
		return banlifecycle.Entry{}, false, nil
	}
	return cloneEntry(entries[len(entries)-1]), true, nil
}

// Active returns every entry currently in StatusActive, across all IPs.
func (s *Store) Active(_ context.Context) ([]banlifecycle.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []banlifecycle.Entry
	for _, entries := range s.history {
		if n := len(entries); n > 0 && entries[n-1].Status == banlifecycle.StatusActive {
			out = append(out, cloneEntry(entries[n-1]))
		}
	}
	return out, nil
}

// Expired returns every active entry whose ExpiresAt is at or before now.
func (s *Store) Expired(_ context.Context, now time.Time) ([]banlifecycle.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []banlifecycle.Entry
	for _, entries := range s.history {
		if n := len(entries); n > 0 {
			last := entries[n-1]
			if last.Status == banlifecycle.StatusActive && !last.ExpiresAt.After(now) {
				out = append(out, cloneEntry(last))
			}
		}
	}
	return out, nil
}

// MarkStatus updates the status of the current (most recent) entry for ip.
// note is accepted for interface parity with the SQLite store but is not
// persisted by this in-memory fake beyond being a no-op placeholder.
func (s *Store) MarkStatus(_ context.Context, ip string, status string, _ string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.history[ip]
	if len(entries) == 0 {
		return nil
	}
	entries[len(entries)-1].Status = status
	s.history[ip] = entries
	return nil
}

// RecordCleanupFailure increments CleanupAttempts and records the
// failure message/timestamp on the current (most recent) entry for ip.
// Status is left unchanged so the next cleanup pass retries.
func (s *Store) RecordCleanupFailure(_ context.Context, ip string, errMsg string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.history[ip]
	if len(entries) == 0 {
		return nil
	}
	last := &entries[len(entries)-1]
	last.CleanupAttempts++
	last.LastCleanupError = errMsg
	last.LastCleanupAttemptAt = time.Now().UTC()
	s.history[ip] = entries
	return nil
}

// Recent returns the most recent entries across all IPs and statuses,
// newest (by CreatedAt) first, capped at limit.
func (s *Store) Recent(_ context.Context, limit int) ([]banlifecycle.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if limit <= 0 {
		limit = 100
	}
	var out []banlifecycle.Entry
	for _, entries := range s.history {
		for _, e := range entries {
			out = append(out, cloneEntry(e))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// RecidiveLevel returns the count of prior non-active entries for ip.
func (s *Store) RecidiveLevel(_ context.Context, ip string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entries := s.history[ip]
	count := 0
	for _, e := range entries {
		if e.Status != banlifecycle.StatusActive {
			count++
		}
	}
	return count, nil
}
