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
}

func NewManager(store events.CheckpointStore, sequences SequenceSource, logger *slog.Logger, retention int) *Manager {
	if retention <= 0 {
		retention = 10
	}
	return &Manager{
		store:     store,
		sequences: sequences,
		logger:    logger,
		retention: retention,
	}
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
	for _, checkpoint := range checkpoints[m.retention:] {
		if err := m.store.DeleteCheckpoint(ctx, scopeID, name, checkpoint.Sequence); err != nil {
			return err
		}
	}
	return nil
}
