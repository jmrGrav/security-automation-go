package main

import (
	"context"
	"sync"

	"github.com/jm/security-automation-go/internal/trustednetworks"
)

// lazyCrowdSecStatusStore wraps a trustednetworks.CrowdSecStatusStore that
// is populated after the scoped SQLite database is opened later in
// daemon startup. The UI server holds it from process start (mirroring
// lazyEvidenceStore): calls before the real store is wired return
// ok=false rather than blocking or erroring, so the UI page renders an
// honest "not available yet" state instead of hanging.
//
// The UI and the cf-allowlist-sync helper never write through this type —
// it is read-only from the UI's perspective; the helper writes directly to
// its own *sqlite.CrowdSecAllowlistStatusStore opened against the same
// scoped database file.
type lazyCrowdSecStatusStore struct {
	mu    sync.RWMutex
	inner trustednetworks.CrowdSecStatusStore
}

func (s *lazyCrowdSecStatusStore) set(inner trustednetworks.CrowdSecStatusStore) {
	s.mu.Lock()
	s.inner = inner
	s.mu.Unlock()
}

func (s *lazyCrowdSecStatusStore) get() trustednetworks.CrowdSecStatusStore {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.inner
}

func (s *lazyCrowdSecStatusStore) GetCrowdSecAllowlistStatus(ctx context.Context, allowlistName string) (trustednetworks.CrowdSecAllowlistStatus, bool, error) {
	if inner := s.get(); inner != nil {
		return inner.GetCrowdSecAllowlistStatus(ctx, allowlistName)
	}
	return trustednetworks.CrowdSecAllowlistStatus{}, false, nil
}

// PutCrowdSecAllowlistStatus exists only to satisfy
// trustednetworks.CrowdSecStatusStore; the UI process never calls it — see
// the type doc comment.
func (s *lazyCrowdSecStatusStore) PutCrowdSecAllowlistStatus(ctx context.Context, status trustednetworks.CrowdSecAllowlistStatus) error {
	if inner := s.get(); inner != nil {
		return inner.PutCrowdSecAllowlistStatus(ctx, status)
	}
	return nil
}

var _ trustednetworks.CrowdSecStatusStore = (*lazyCrowdSecStatusStore)(nil)
