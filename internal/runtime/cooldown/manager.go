package cooldown

import (
	"context"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/state"
)

// Manager handles cooldown periods for autonomous actions.
type Manager struct {
	mu    sync.Mutex
	store *state.StateStore
}

func NewManager(store *state.StateStore) *Manager {
	return &Manager{store: store}
}

// Start initiates a cooldown period for a specific reason.
func (m *Manager) Start(ctx context.Context, duration time.Duration, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	curState, err := m.store.Load()
	if err != nil {
		return err
	}

	expiry := time.Now().Add(duration)
	if curState.Cooldowns == nil {
		curState.Cooldowns = make(map[string]time.Time)
	}
	curState.Cooldowns[reason] = expiry

	return m.store.Save(curState)
}

// IsActive checks if any cooldown is currently active.
func (m *Manager) IsActive(reason string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	curState, _ := m.store.Load()
	if curState.Cooldowns == nil {
		return false
	}

	expiry, ok := curState.Cooldowns[reason]
	if !ok {
		return false
	}

	return time.Now().Before(expiry)
}

// Remaining returns the longest remaining cooldown duration.
func (m *Manager) Remaining() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()

	curState, _ := m.store.Load()
	if curState.Cooldowns == nil {
		return 0
	}

	var max time.Duration
	now := time.Now()
	for _, expiry := range curState.Cooldowns {
		rem := expiry.Sub(now)
		if rem > max {
			max = rem
		}
	}
	return max
}
