package main

import (
	"context"
	"sync"

	"github.com/jm/security-automation-go/internal/cloudflare/enforcementlog"
)

// lazyEnforcementEventStore mirrors lazyBanLifecycleStore: the UI server
// goroutine starts before the scoped runtime SQLite DB is opened, so it
// must hold a reference it can construct immediately and have populated
// later via set(), rather than binding permanently to the unscoped
// bootstrap DB (which never receives any enforcement-event writes).
type lazyEnforcementEventStore struct {
	mu    sync.RWMutex
	inner enforcementlog.Store
}

func (s *lazyEnforcementEventStore) set(inner enforcementlog.Store) {
	s.mu.Lock()
	s.inner = inner
	s.mu.Unlock()
}

func (s *lazyEnforcementEventStore) get() enforcementlog.Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner
}

func (s *lazyEnforcementEventStore) Append(ctx context.Context, e enforcementlog.Event) error {
	if inner := s.get(); inner != nil {
		return inner.Append(ctx, e)
	}
	return nil
}

func (s *lazyEnforcementEventStore) Recent(ctx context.Context, limit int) ([]enforcementlog.Event, error) {
	if inner := s.get(); inner != nil {
		return inner.Recent(ctx, limit)
	}
	return nil, nil
}

func (s *lazyEnforcementEventStore) LastSuccess(ctx context.Context) (enforcementlog.Event, bool, error) {
	if inner := s.get(); inner != nil {
		return inner.LastSuccess(ctx)
	}
	return enforcementlog.Event{}, false, nil
}

func (s *lazyEnforcementEventStore) LastFailure(ctx context.Context) (enforcementlog.Event, bool, error) {
	if inner := s.get(); inner != nil {
		return inner.LastFailure(ctx)
	}
	return enforcementlog.Event{}, false, nil
}

var _ enforcementlog.Store = (*lazyEnforcementEventStore)(nil)
