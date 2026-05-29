package memory

import (
	"sync"
	"time"
)

// Store persists and analyzes historical drift data.
type Store struct {
	mu     sync.RWMutex
	memory map[string]*DriftMemory // fingerprint -> memory
}

func NewStore() *Store {
	return &Store{
		memory: make(map[string]*DriftMemory),
	}
}

// Record updates the historical memory for a drift fingerprint.
func (s *Store) Record(fingerprint string, score float64, scopeID, leaderID string) *DriftMemory {
	s.mu.Lock()
	defer s.mu.Unlock()

	m, ok := s.memory[fingerprint]
	if !ok {
		m = &DriftMemory{
			Fingerprint:   fingerprint,
			FirstSeenAt:   time.Now().UTC(),
			Occurrences:   1,
			SeverityTrend: TrendStable,
		}
		s.memory[fingerprint] = m
	} else {
		m.Occurrences++
		if score > m.LastRiskScore {
			m.SeverityTrend = TrendWorsening
		} else if score < m.LastRiskScore {
			m.SeverityTrend = TrendImproving
		} else {
			m.SeverityTrend = TrendStable
		}
	}

	m.LastSeenAt = time.Now().UTC()
	m.LastRiskScore = score
	m.LastScopeID = scopeID
	m.LastLeaderID = leaderID

	return m
}

// Get returns the historical memory for a fingerprint.
func (s *Store) Get(fingerprint string) (*DriftMemory, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.memory[fingerprint]
	return m, ok
}

// GlobalPressure correlates drifts across scopes.
func (s *Store) DetectGlobalAnomaly(window time.Duration, threshold int) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now()
	recentOccurrences := 0
	for _, m := range s.memory {
		if now.Sub(m.LastSeenAt) < window {
			recentOccurrences++
		}
	}
	return recentOccurrences > threshold
}
