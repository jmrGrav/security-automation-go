package checkpoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

const DefaultRuntimeCheckpointName = "runtime-state"

type SequenceSource interface {
	GetLastSequence(ctx context.Context, scopeID string) (uint64, error)
}

type Manager struct {
	store     events.CheckpointStore
	sequences SequenceSource
	logger    *slog.Logger
	retention int
	archive   ArchiveCompactor
}

type Option func(*Manager)

type ArchiveCompactor interface {
	CompactRawArchive(ctx context.Context, scopeID string, checkpointName string, throughSequence uint64) (ArchiveCompactionStats, error)
}

type ArchiveCompactionStats struct {
	SafeSequence      uint64
	HotEntries        int64
	WarmEntries       int64
	ColdEntries       int64
	ReplaySafeEntries int64
	PurgeCandidates   int64
	Compactions       int64
	Rotations         int64
	StorageBytes      int64
}

func WithArchiveCompactor(compactor ArchiveCompactor) Option {
	return func(m *Manager) {
		m.archive = compactor
	}
}

func NewManager(store events.CheckpointStore, sequences SequenceSource, logger *slog.Logger, retention int, opts ...Option) *Manager {
	if retention <= 0 {
		retention = 10
	}
	m := &Manager{
		store:     store,
		sequences: sequences,
		logger:    logger,
		retention: retention,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(m)
		}
	}
	return m
}

func (m *Manager) SaveRuntimeState(ctx context.Context, scopeID string, trigger string, event events.Event, state models.RuntimeState) (events.Checkpoint, error) {
	return m.SaveNamedRuntimeState(ctx, DefaultRuntimeCheckpointName, scopeID, trigger, event, state)
}

func (m *Manager) SaveNamedRuntimeState(ctx context.Context, name string, scopeID string, trigger string, event events.Event, state models.RuntimeState) (events.Checkpoint, error) {
	const op = "runtime.checkpoint.Manager.SaveNamedRuntimeState"

	stateBytes, err := json.Marshal(state)
	if err != nil {
		return events.Checkpoint{}, apperr.Wrap(op, err)
	}

	seq := event.Sequence
	if seq == 0 && m.sequences != nil {
		seq, err = m.sequences.GetLastSequence(ctx, scopeID)
		if err != nil {
			return events.Checkpoint{}, apperr.Wrap(op, err)
		}
	}

	checkpoint := events.Checkpoint{
		Name:          name,
		ScopeID:       scopeID,
		Sequence:      seq,
		EventID:       event.ID,
		State:         json.RawMessage(stateBytes),
		SchemaVersion: events.SchemaVersion,
		CreatedAt:     event.Timestamp.UTC(),
		Metadata: map[string]any{
			"trigger":          trigger,
			"event_type":       event.Type,
			"event_category":   string(event.Category),
			"correlation_id":   event.CorrelationID,
			"lifecycle_status": state.Lifecycle.Status.String(),
			"epoch_id":         state.CurrentEpoch.ID,
			"fencing_token":    state.CurrentEpoch.Generation,
		},
	}
	if checkpoint.CreatedAt.IsZero() {
		checkpoint.CreatedAt = state.Lifecycle.LastUpdatedAt.UTC()
	}
	checkpoint.Checksum = checksumFor(checkpoint)

	if err := m.store.SaveCheckpoint(ctx, checkpoint); err != nil {
		return events.Checkpoint{}, apperr.Wrap(op, err)
	}
	if err := m.compact(ctx, scopeID, name); err != nil {
		return events.Checkpoint{}, apperr.Wrap(op, err)
	}
	if _, err := m.compactArchive(ctx, scopeID, name); err != nil {
		return events.Checkpoint{}, apperr.Wrap(op, err)
	}

	if m.logger != nil {
		m.logger.Debug("runtime_checkpoint_saved",
			"name", checkpoint.Name,
			"scope_id", checkpoint.ScopeID,
			"sequence", checkpoint.Sequence,
			"trigger", trigger,
		)
	}

	return checkpoint, nil
}

func (m *Manager) LatestRuntimeState(ctx context.Context, scopeID string) (models.RuntimeState, events.Checkpoint, error) {
	return m.LatestNamedRuntimeState(ctx, scopeID, DefaultRuntimeCheckpointName)
}

func (m *Manager) LatestNamedRuntimeState(ctx context.Context, scopeID string, name string) (models.RuntimeState, events.Checkpoint, error) {
	const op = "runtime.checkpoint.Manager.LatestNamedRuntimeState"

	checkpoint, err := m.store.LatestCheckpoint(ctx, scopeID, name)
	if err != nil {
		return models.RuntimeState{}, events.Checkpoint{}, err
	}
	if err := ValidateCheckpoint(checkpoint); err != nil {
		return models.RuntimeState{}, events.Checkpoint{}, apperr.Wrap(op, err)
	}

	var state models.RuntimeState
	if err := json.Unmarshal(checkpoint.State, &state); err != nil {
		return models.RuntimeState{}, events.Checkpoint{}, apperr.Wrap(op, err)
	}
	return state, checkpoint, nil
}

func (m *Manager) InvalidateStale(ctx context.Context, scopeID string, name string) error {
	const op = "runtime.checkpoint.Manager.InvalidateStale"

	if m.sequences == nil {
		return nil
	}
	lastSequence, err := m.sequences.GetLastSequence(ctx, scopeID)
	if err != nil {
		return apperr.Wrap(op, err)
	}

	checkpoints, err := m.store.ListCheckpoints(ctx, scopeID, name, 0)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	for _, checkpoint := range checkpoints {
		if checkpoint.Sequence > lastSequence {
			if err := m.store.DeleteCheckpoint(ctx, scopeID, name, checkpoint.Sequence); err != nil {
				return apperr.Wrap(op, err)
			}
		}
	}
	return nil
}

func ValidateCheckpoint(checkpoint events.Checkpoint) error {
	const op = "runtime.checkpoint.ValidateCheckpoint"

	expected := checksumFor(checkpoint)
	if checkpoint.Checksum != expected {
		return apperr.Newf(op, "checkpoint checksum mismatch for %s/%s at sequence %d", checkpoint.ScopeID, checkpoint.Name, checkpoint.Sequence)
	}
	return nil
}

func checksumFor(checkpoint events.Checkpoint) string {
	payload, _ := json.Marshal(struct {
		Name          string          `json:"name"`
		ScopeID       string          `json:"scope_id"`
		Sequence      uint64          `json:"sequence"`
		EventID       int64           `json:"event_id"`
		State         json.RawMessage `json:"state"`
		Metadata      map[string]any  `json:"metadata,omitempty"`
		SchemaVersion int             `json:"schema_version"`
		CreatedAt     string          `json:"created_at"`
	}{
		Name:          checkpoint.Name,
		ScopeID:       checkpoint.ScopeID,
		Sequence:      checkpoint.Sequence,
		EventID:       checkpoint.EventID,
		State:         checkpoint.State,
		Metadata:      checkpoint.Metadata,
		SchemaVersion: checkpoint.SchemaVersion,
		CreatedAt:     canonicalTime(checkpoint.CreatedAt),
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func canonicalTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339Nano)
}

func (m *Manager) compact(ctx context.Context, scopeID string, name string) error {
	if m.retention <= 0 {
		return nil
	}
	checkpoints, err := m.store.ListCheckpoints(ctx, scopeID, name, 0)
	if err != nil {
		return err
	}
	if len(checkpoints) <= m.retention {
		return nil
	}

	retained := checkpoints[:m.retention]
	for _, checkpoint := range retained {
		if err := ValidateCheckpoint(checkpoint); err != nil {
			return err
		}
	}

	for _, checkpoint := range checkpoints[m.retention:] {
		if err := m.store.DeleteCheckpoint(ctx, scopeID, name, checkpoint.Sequence); err != nil {
			return err
		}
	}

	if compactor, ok := m.store.(events.RawArchiveCompactor); ok {
		if err := compactor.CompactRawArchive(ctx, scopeID, name, retained[len(retained)-1].Sequence); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) compactArchive(ctx context.Context, scopeID string, name string) (ArchiveCompactionStats, error) {
	if m == nil || m.archive == nil {
		return ArchiveCompactionStats{}, nil
	}
	safeSequence, ok, err := m.safeArchiveSequence(ctx, scopeID, name)
	if err != nil {
		return ArchiveCompactionStats{}, err
	}
	if !ok || safeSequence == 0 {
		return ArchiveCompactionStats{}, nil
	}
	return m.archive.CompactRawArchive(ctx, scopeID, name, safeSequence)
}

func (m *Manager) safeArchiveSequence(ctx context.Context, scopeID string, name string) (uint64, bool, error) {
	checkpoints, err := m.store.ListCheckpoints(ctx, scopeID, name, 0)
	if err != nil {
		return 0, false, err
	}
	for i := len(checkpoints) - 1; i >= 0; i-- {
		checkpoint := checkpoints[i]
		if err := ValidateCheckpoint(checkpoint); err == nil {
			return checkpoint.Sequence, true, nil
		}
	}
	return 0, false, nil
}
