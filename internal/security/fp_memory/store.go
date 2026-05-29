// Package fp_memory stores suspected false-positive patterns with temporal
// decay. It is intentionally lightweight and replay-friendly so higher layers
// can penalize repeated misleading signals without coupling policy logic to a
// specific database backend.
package fp_memory

import (
	"sync"
	"time"
)

type Entry struct {
	Key         string    `json:"key"`
	Count       int       `json:"count"`
	LastSeen    time.Time `json:"last_seen"`
	Penalty     float64   `json:"penalty"`
	Category    string    `json:"category"`
	Source      string    `json:"source"`
	SuspectedFP bool      `json:"suspected_false_positive"`
}

type Store struct {
	mu       sync.RWMutex
	entries  map[string]Entry
	halfLife time.Duration
}

func New(halfLife time.Duration) *Store {
	if halfLife <= 0 {
		halfLife = 24 * time.Hour
	}
	return &Store{
		entries:  make(map[string]Entry),
		halfLife: halfLife,
	}
}

func (s *Store) Remember(key string, category string, source string, suspected bool, now time.Time) Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry := s.entries[key]
	entry.Key = key
	entry.Category = category
	entry.Source = source
	entry.SuspectedFP = suspected
	entry.Count++
	entry.LastSeen = now.UTC()
	if suspected {
		entry.Penalty += 0.15
		if entry.Penalty > 0.9 {
			entry.Penalty = 0.9
		}
	}
	s.entries[key] = entry
	return entry
}

func (s *Store) Penalty(key string, now time.Time) float64 {
	s.mu.RLock()
	entry, ok := s.entries[key]
	s.mu.RUnlock()
	if !ok {
		return 0
	}
	age := now.UTC().Sub(entry.LastSeen)
	if age <= 0 {
		return entry.Penalty
	}
	factor := 1.0 / (1.0 + age.Hours()/s.halfLife.Hours())
	return entry.Penalty * factor
}
