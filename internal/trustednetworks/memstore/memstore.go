// Package memstore is an in-memory trustednetworks.Store, used for tests
// and any in-process composition that doesn't need durability.
package memstore

import (
	"context"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/trustednetworks"
)

type Store struct {
	mu      sync.Mutex
	entries map[string]trustednetworks.Entry
}

func New() *Store {
	return &Store{entries: make(map[string]trustednetworks.Entry)}
}

var _ trustednetworks.Store = (*Store)(nil)

func (s *Store) List(_ context.Context) ([]trustednetworks.Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]trustednetworks.Entry, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, e)
	}
	return out, nil
}

func (s *Store) Get(_ context.Context, value string) (trustednetworks.Entry, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[value]
	return e, ok, nil
}

func (s *Store) Upsert(_ context.Context, e trustednetworks.Entry) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	if existing, ok := s.entries[e.Value]; ok {
		e.CreatedAt = existing.CreatedAt
	} else {
		e.CreatedAt = now
	}
	e.UpdatedAt = now
	s.entries[e.Value] = e
	return nil
}

func (s *Store) Remove(_ context.Context, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, value)
	return nil
}
