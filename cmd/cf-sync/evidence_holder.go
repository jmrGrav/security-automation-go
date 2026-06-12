package main

import (
	"context"
	"sync"

	"github.com/jm/security-automation-go/internal/services/reporting"
)

// lazyEvidenceStore wraps an EvidenceStore that is populated after daemon
// startup. The UI server holds it from process start; calls before the daemon
// wires the real store return empty results rather than errors, preserving
// the property that the UI goroutine survives daemon startup failures.
type lazyEvidenceStore struct {
	mu    sync.RWMutex
	inner reporting.EvidenceStore
}

func (s *lazyEvidenceStore) set(inner reporting.EvidenceStore) {
	s.mu.Lock()
	s.inner = inner
	s.mu.Unlock()
}

func (s *lazyEvidenceStore) get() reporting.EvidenceStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner
}

func (s *lazyEvidenceStore) Append(ctx context.Context, ev reporting.DecisionEvidence) error {
	if inner := s.get(); inner != nil {
		return inner.Append(ctx, ev)
	}
	return nil
}

func (s *lazyEvidenceStore) List(ctx context.Context, limit int) ([]reporting.DecisionEvidence, error) {
	if inner := s.get(); inner != nil {
		return inner.List(ctx, limit)
	}
	return nil, nil
}

func (s *lazyEvidenceStore) Get(ctx context.Context, evidenceID string) (reporting.DecisionEvidence, bool, error) {
	if inner := s.get(); inner != nil {
		return inner.Get(ctx, evidenceID)
	}
	return reporting.DecisionEvidence{}, false, nil
}

func (s *lazyEvidenceStore) Search(ctx context.Context, opts reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	if inner := s.get(); inner != nil {
		return inner.Search(ctx, opts)
	}
	return nil, nil
}
