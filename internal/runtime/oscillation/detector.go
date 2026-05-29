package oscillation

import (
	"sync"
	"time"
)

type ActionKey struct {
	SIK  string
	Type string // create, update, delete
}

// Detector identifies repeated action cycles.
type Detector struct {
	mu      sync.Mutex
	history map[ActionKey][]time.Time
	limit   int
	window  time.Duration
}

func NewDetector(limit int, window time.Duration) *Detector {
	return &Detector{
		history: make(map[ActionKey][]time.Time),
		limit:   limit,
		window:  window,
	}
}

// Record checks if an action is part of an oscillation.
func (d *Detector) Record(sik, opType string) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	key := ActionKey{SIK: sik, Type: opType}
	now := time.Now()

	// Purge old entries
	times := d.history[key]
	var valid []time.Time
	for _, t := range times {
		if now.Sub(t) < d.window {
			valid = append(valid, t)
		}
	}

	valid = append(valid, now)
	d.history[key] = valid

	return len(valid) > d.limit
}
