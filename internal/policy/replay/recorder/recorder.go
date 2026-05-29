package recorder

import (
	"context"
	"log/slog"
	"sync"

	"github.com/jm/security-automation-go/internal/policy/replay/evidence"
	"github.com/jm/security-automation-go/internal/runtime/journal"
)

// Recorder captures and persists governance evidence.
type Recorder struct {
	mu      sync.RWMutex
	journal journal.JournalStore
	logger  *slog.Logger
	archive map[string]evidence.GovernanceEvidence
}

func New(j journal.JournalStore, logger *slog.Logger) *Recorder {
	return &Recorder{
		journal: j,
		logger:  logger,
		archive: make(map[string]evidence.GovernanceEvidence),
	}
}

// Record persists a single evidence record.
func (r *Recorder) Record(ctx context.Context, e evidence.GovernanceEvidence) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	const op = "policy.replay.recorder.Record"

	r.archive[e.EvidenceID] = e

	r.logger.Info("governance_evidence_recorded",
		"evidence_id", e.EvidenceID,
		"trace_id", e.TraceID,
		"decision", e.FinalDecision,
	)

	// In a real implementation, we'd persist this to a dedicated JSONL or database.
	// For now, we rely on the memory archive and existing journal events.

	return nil
}

// Get returns a specific evidence record.
func (r *Recorder) Get(id string) (evidence.GovernanceEvidence, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.archive[id]
	return e, ok
}

// List returns all recorded evidence.
func (r *Recorder) List() []evidence.GovernanceEvidence {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]evidence.GovernanceEvidence, 0, len(r.archive))
	for _, e := range r.archive {
		out = append(out, e)
	}
	return out
}
