package checkpoint

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

type checkpointStore struct {
	checkpoints []events.Checkpoint
	lastSeq     uint64
}

func (s *checkpointStore) SaveCheckpoint(_ context.Context, checkpoint events.Checkpoint) error {
	s.checkpoints = append(s.checkpoints, checkpoint)
	return nil
}

func (s *checkpointStore) LatestCheckpoint(_ context.Context, scopeID string, name string) (events.Checkpoint, error) {
	for i := len(s.checkpoints) - 1; i >= 0; i-- {
		cp := s.checkpoints[i]
		if cp.ScopeID == scopeID && cp.Name == name {
			return cp, nil
		}
	}
	return events.Checkpoint{}, events.ErrCheckpointNotFound
}

func (s *checkpointStore) ListCheckpoints(_ context.Context, scopeID string, name string, limit int) ([]events.Checkpoint, error) {
	var out []events.Checkpoint
	for i := len(s.checkpoints) - 1; i >= 0; i-- {
		cp := s.checkpoints[i]
		if cp.ScopeID == scopeID && cp.Name == name {
			out = append(out, cp)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *checkpointStore) DeleteCheckpoint(_ context.Context, scopeID string, name string, sequence uint64) error {
	var kept []events.Checkpoint
	for _, cp := range s.checkpoints {
		if cp.ScopeID == scopeID && cp.Name == name && cp.Sequence == sequence {
			continue
		}
		kept = append(kept, cp)
	}
	s.checkpoints = kept
	return nil
}

func (s *checkpointStore) GetLastSequence(_ context.Context, _ string) (uint64, error) {
	return s.lastSeq, nil
}

func TestManagerSaveAndLoadRuntimeState(t *testing.T) {
	store := &checkpointStore{lastSeq: 3}
	mgr := NewManager(store, store, nil, 3)
	state := models.RuntimeState{
		LastRunID: "run-1",
		Lifecycle: models.LifecycleState{
			Status:        models.StatusPlanning,
			LastUpdatedAt: time.Now().UTC(),
		},
		CurrentEpoch: models.Epoch{
			ID:         "epoch-1",
			Generation: 42,
		},
	}
	event := events.Event{
		ID:            9,
		Sequence:      3,
		ScopeID:       "scope-a",
		Type:          events.TypeLifecycleTransition,
		Category:      events.CategoryLifecycle,
		CorrelationID: "corr-1",
		Timestamp:     time.Now().UTC(),
	}

	cp, err := mgr.SaveRuntimeState(context.Background(), "scope-a", "transition:planning", event, state)
	if err != nil {
		t.Fatalf("save runtime state: %v", err)
	}
	if cp.Sequence != 3 {
		t.Fatalf("expected sequence 3, got %d", cp.Sequence)
	}
	if err := ValidateCheckpoint(cp); err != nil {
		t.Fatalf("validate checkpoint: %v", err)
	}

	got, latest, err := mgr.LatestRuntimeState(context.Background(), "scope-a")
	if err != nil {
		t.Fatalf("latest runtime state: %v", err)
	}
	if got.LastRunID != "run-1" || latest.Sequence != 3 {
		t.Fatalf("unexpected recovered state/checkpoint: %+v %+v", got, latest)
	}
}

func TestManagerRetentionAndStaleInvalidation(t *testing.T) {
	store := &checkpointStore{lastSeq: 2}
	mgr := NewManager(store, store, nil, 2)
	state := models.RuntimeState{Lifecycle: models.LifecycleState{Status: models.StatusIdle, LastUpdatedAt: time.Now().UTC()}}

	for seq := uint64(1); seq <= 4; seq++ {
		_, err := mgr.SaveNamedRuntimeState(context.Background(), "runtime-state", "scope-a", "test", events.Event{
			ID:        int64(seq),
			Sequence:  seq,
			ScopeID:   "scope-a",
			Timestamp: time.Now().UTC(),
		}, state)
		if err != nil {
			t.Fatalf("save checkpoint %d: %v", seq, err)
		}
	}

	list, err := store.ListCheckpoints(context.Background(), "scope-a", "runtime-state", 0)
	if err != nil {
		t.Fatalf("list checkpoints: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("expected retention to keep 2 checkpoints, got %d", len(list))
	}

	stale := events.Checkpoint{
		Name:          "runtime-state",
		ScopeID:       "scope-a",
		Sequence:      99,
		EventID:       99,
		State:         json.RawMessage(`{}`),
		Metadata:      map[string]any{"trigger": "stale"},
		SchemaVersion: events.SchemaVersion,
		CreatedAt:     time.Now().UTC(),
	}
	stale.Checksum = checksumFor(stale)
	store.checkpoints = append(store.checkpoints, stale)
	if err := mgr.InvalidateStale(context.Background(), "scope-a", "runtime-state"); err != nil {
		t.Fatalf("invalidate stale: %v", err)
	}
	list, _ = store.ListCheckpoints(context.Background(), "scope-a", "runtime-state", 0)
	for _, cp := range list {
		if cp.Sequence > 2 {
			t.Fatalf("expected stale checkpoint removal, found sequence %d", cp.Sequence)
		}
	}
}

func TestValidateCheckpointDetectsCanonicalTampering(t *testing.T) {
	cp := events.Checkpoint{
		Name:          "runtime-state",
		ScopeID:       "scope-a",
		Sequence:      7,
		EventID:       17,
		State:         json.RawMessage(`{"status":"executing"}`),
		Metadata:      map[string]any{"trigger": "test", "epoch_id": "ep-1"},
		SchemaVersion: events.SchemaVersion,
		CreatedAt:     time.Date(2026, 5, 27, 10, 0, 0, 0, time.UTC),
	}
	cp.Checksum = checksumFor(cp)

	if err := ValidateCheckpoint(cp); err != nil {
		t.Fatalf("expected valid checkpoint: %v", err)
	}

	t.Run("event_id", func(t *testing.T) {
		tampered := cp
		tampered.EventID++
		if err := ValidateCheckpoint(tampered); err == nil {
			t.Fatal("expected checksum mismatch on event id change")
		}
	})
	t.Run("metadata", func(t *testing.T) {
		tampered := cp
		tampered.Metadata = map[string]any{"trigger": "test", "epoch_id": "ep-2"}
		if err := ValidateCheckpoint(tampered); err == nil {
			t.Fatal("expected checksum mismatch on metadata change")
		}
	})
	t.Run("schema_version", func(t *testing.T) {
		tampered := cp
		tampered.SchemaVersion++
		if err := ValidateCheckpoint(tampered); err == nil {
			t.Fatal("expected checksum mismatch on schema version change")
		}
	})
	t.Run("state", func(t *testing.T) {
		tampered := cp
		tampered.State = json.RawMessage(`{"status":"failed"}`)
		if err := ValidateCheckpoint(tampered); err == nil {
			t.Fatal("expected checksum mismatch on state change")
		}
	})
	if cp.Checksum != checksumFor(cp) {
		t.Fatal("expected stable checksum")
	}
}
