package main

import (
	"context"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
)

// lazyBanLifecycleStore wraps a banlifecycle.Store that is populated after
// daemon startup, once the scoped runtime SQLite DB is opened. The UI server
// goroutine starts before scope resolution (see runtime.go) and must hold a
// reference it can construct immediately; without this indirection it binds
// permanently to the unscoped bootstrap DB, which never receives any
// lifecycle writes (those go to the scoped DB the daemon opens later) — the
// UI's /ban-lifecycle and /sync pages would render placeholders forever even
// though real bans exist. Mirrors lazyEvidenceStore's pattern.
type lazyBanLifecycleStore struct {
	mu    sync.RWMutex
	inner banlifecycle.Store
}

func (s *lazyBanLifecycleStore) set(inner banlifecycle.Store) {
	s.mu.Lock()
	s.inner = inner
	s.mu.Unlock()
}

func (s *lazyBanLifecycleStore) get() banlifecycle.Store {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner
}

func (s *lazyBanLifecycleStore) Upsert(ctx context.Context, e banlifecycle.Entry) error {
	if inner := s.get(); inner != nil {
		return inner.Upsert(ctx, e)
	}
	return nil
}

func (s *lazyBanLifecycleStore) Get(ctx context.Context, ip string) (banlifecycle.Entry, bool, error) {
	if inner := s.get(); inner != nil {
		return inner.Get(ctx, ip)
	}
	return banlifecycle.Entry{}, false, nil
}

func (s *lazyBanLifecycleStore) Active(ctx context.Context) ([]banlifecycle.Entry, error) {
	if inner := s.get(); inner != nil {
		return inner.Active(ctx)
	}
	return nil, nil
}

func (s *lazyBanLifecycleStore) Expired(ctx context.Context, now time.Time) ([]banlifecycle.Entry, error) {
	if inner := s.get(); inner != nil {
		return inner.Expired(ctx, now)
	}
	return nil, nil
}

func (s *lazyBanLifecycleStore) MarkStatus(ctx context.Context, ip string, status string, note string) error {
	if inner := s.get(); inner != nil {
		return inner.MarkStatus(ctx, ip, status, note)
	}
	return nil
}

func (s *lazyBanLifecycleStore) RecordCleanupFailure(ctx context.Context, ip string, errMsg string) error {
	if inner := s.get(); inner != nil {
		return inner.RecordCleanupFailure(ctx, ip, errMsg)
	}
	return nil
}

func (s *lazyBanLifecycleStore) Recent(ctx context.Context, limit int) ([]banlifecycle.Entry, error) {
	if inner := s.get(); inner != nil {
		return inner.Recent(ctx, limit)
	}
	return nil, nil
}

func (s *lazyBanLifecycleStore) RecidiveLevel(ctx context.Context, ip string) (int, error) {
	if inner := s.get(); inner != nil {
		return inner.RecidiveLevel(ctx, ip)
	}
	return 0, nil
}

var _ banlifecycle.Store = (*lazyBanLifecycleStore)(nil)
