package main

import (
	"context"
	"sync"

	"github.com/jm/security-automation-go/internal/runtime/events"
)

// lazyEventStore wraps the scoped runtime event journal (events.EventStore),
// which is opened after the UI goroutine starts (same ordering problem as
// lazyBanLifecycleStore: the UI must hold an indirection it can construct
// immediately, then resolve against the real scoped store once the daemon
// calls set(...)). Used by the /timeline page to surface real runtime
// lifecycle lineage (sequence numbers, correlation ids) instead of leaving it
// permanently unread.
type lazyEventStore struct {
	mu    sync.RWMutex
	inner events.EventStore
}

func (s *lazyEventStore) set(inner events.EventStore) {
	s.mu.Lock()
	s.inner = inner
	s.mu.Unlock()
}

func (s *lazyEventStore) get() events.EventStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner
}

func (s *lazyEventStore) Append(ctx context.Context, event *events.Event) error {
	if inner := s.get(); inner != nil {
		return inner.Append(ctx, event)
	}
	return nil
}

func (s *lazyEventStore) List(ctx context.Context, scopeID string, afterSequence uint64) ([]events.Event, error) {
	if inner := s.get(); inner != nil {
		return inner.List(ctx, scopeID, afterSequence)
	}
	return nil, nil
}

func (s *lazyEventStore) GetLastSequence(ctx context.Context, scopeID string) (uint64, error) {
	if inner := s.get(); inner != nil {
		return inner.GetLastSequence(ctx, scopeID)
	}
	return 0, nil
}

var _ events.EventStore = (*lazyEventStore)(nil)
