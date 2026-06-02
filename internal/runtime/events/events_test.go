package events

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type memoryStore struct {
	mu          sync.Mutex
	events      []Event
	checkpoints []Checkpoint
}

func (s *memoryStore) Append(_ context.Context, event *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var seq uint64 = 1
	for _, existing := range s.events {
		if existing.ScopeID == event.ScopeID && existing.Sequence >= seq {
			seq = existing.Sequence + 1
		}
	}
	event.ID = int64(len(s.events) + 1)
	event.Sequence = seq
	s.events = append(s.events, *event)
	return nil
}

func (s *memoryStore) List(_ context.Context, scopeID string, afterSequence uint64) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Event
	for _, event := range s.events {
		if event.ScopeID == scopeID && event.Sequence > afterSequence {
			out = append(out, event)
		}
	}
	return out, nil
}

func (s *memoryStore) GetLastSequence(_ context.Context, scopeID string) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var last uint64
	for _, event := range s.events {
		if event.ScopeID == scopeID && event.Sequence > last {
			last = event.Sequence
		}
	}
	return last, nil
}

func (s *memoryStore) SaveCheckpoint(_ context.Context, checkpoint Checkpoint) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpoints = append(s.checkpoints, checkpoint)
	return nil
}

func (s *memoryStore) LatestCheckpoint(_ context.Context, scopeID string, name string) (Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.checkpoints) - 1; i >= 0; i-- {
		cp := s.checkpoints[i]
		if cp.ScopeID == scopeID && cp.Name == name {
			return cp, nil
		}
	}
	return Checkpoint{}, ErrCheckpointNotFound
}

func (s *memoryStore) ListCheckpoints(_ context.Context, scopeID string, name string, limit int) ([]Checkpoint, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	var out []Checkpoint
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

func (s *memoryStore) DeleteCheckpoint(_ context.Context, scopeID string, name string, sequence uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var kept []Checkpoint
	for _, cp := range s.checkpoints {
		if cp.ScopeID == scopeID && cp.Name == name && cp.Sequence == sequence {
			continue
		}
		kept = append(kept, cp)
	}
	s.checkpoints = kept
	return nil
}

func TestBusPublishEventSequentialAndSubscriberUsesCallerContext(t *testing.T) {
	store := &memoryStore{}
	logger := slog.New(slog.NewTextHandler(testWriter{t: t}, nil))
	bus := NewBus(store, logger)

	ctxKey := struct{}{}
	ctx := context.WithValue(context.Background(), ctxKey, "trace-123")

	var seenValue any
	bus.Subscribe(CategoryLifecycle, func(ctx context.Context, event Event) error {
		seenValue = ctx.Value(ctxKey)
		if event.Sequence != 1 {
			t.Fatalf("expected sequence 1, got %d", event.Sequence)
		}
		return nil
	})

	ev, err := bus.PublishEvent(ctx, PublishRequest{
		Category:      CategoryLifecycle,
		Type:          "run.started",
		ScopeID:       "scope-a",
		CorrelationID: "corr-1",
		Payload:       map[string]any{"step": "discover"},
	})
	if err != nil {
		t.Fatalf("publish event: %v", err)
	}
	if seenValue != "trace-123" {
		t.Fatalf("subscriber did not receive caller context")
	}
	if ev.Sequence != 1 || ev.ID != 1 {
		t.Fatalf("unexpected event identity: %+v", ev)
	}
	if string(ev.Payload) != `{"step":"discover"}` {
		t.Fatalf("unexpected payload: %s", string(ev.Payload))
	}
}

func TestBusPublishEventPropagatesSubscriberErrors(t *testing.T) {
	store := &memoryStore{}
	bus := NewBus(store, nil)
	want := errors.New("subscriber failed")
	bus.Subscribe(CategoryPolicy, func(context.Context, Event) error { return want })

	_, err := bus.PublishEvent(context.Background(), PublishRequest{
		Category: CategoryPolicy,
		Type:     "policy.denied",
		ScopeID:  "scope-a",
		Payload:  map[string]any{"decision": "deny"},
	})
	if err == nil {
		t.Fatal("expected subscriber error")
	}
}

type replayState struct {
	restored []Checkpoint
	applied  []uint64
}

func (r *replayState) RestoreCheckpoint(_ context.Context, checkpoint Checkpoint) error {
	r.restored = append(r.restored, checkpoint)
	return nil
}

func (r *replayState) ApplyEvent(_ context.Context, event Event) error {
	r.applied = append(r.applied, event.Sequence)
	return nil
}

type testWriter struct {
	t *testing.T
}

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(string(p))
	return len(p), nil
}

func TestReplayWithCheckpointStartsAfterCheckpointSequence(t *testing.T) {
	store := &memoryStore{
		events: []Event{
			{ID: 1, Sequence: 1, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":1}`), Timestamp: time.Now().UTC()},
			{ID: 2, Sequence: 2, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":2}`), Timestamp: time.Now().UTC()},
			{ID: 3, Sequence: 3, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":3}`), Timestamp: time.Now().UTC()},
		},
		checkpoints: []Checkpoint{
			{
				Name:          "runtime-state",
				ScopeID:       "scope-a",
				Sequence:      2,
				EventID:       2,
				State:         json.RawMessage(`{"status":"planning"}`),
				Metadata:      map[string]any{"trigger": "checkpoint"},
				SchemaVersion: SchemaVersion,
				CreatedAt:     time.Now().UTC(),
			},
		},
	}
	store.checkpoints[0].Checksum = checkpointReplayChecksum(store.checkpoints[0].Name, store.checkpoints[0].ScopeID, store.checkpoints[0].Sequence, store.checkpoints[0].EventID, store.checkpoints[0].State, store.checkpoints[0].Metadata, store.checkpoints[0].SchemaVersion, store.checkpoints[0].CreatedAt)
	state := &replayState{}
	result, err := ReplayWithOptions(context.Background(), store, "scope-a", state, ReplayOptions{
		CheckpointName: "runtime-state",
	})
	if err != nil {
		t.Fatalf("replay with checkpoint: %v", err)
	}
	if !result.UsedCheckpoint || result.StartedAfterSequence != 2 || result.FinalSequence != 3 {
		t.Fatalf("unexpected replay result: %+v", result)
	}
	if len(state.restored) != 1 {
		t.Fatalf("expected one restored checkpoint, got %d", len(state.restored))
	}
	if len(state.applied) != 1 || state.applied[0] != 3 {
		t.Fatalf("expected to apply only sequence 3, got %v", state.applied)
	}
}

func TestReplayWithCheckpointFallsBackToEarlierValidCheckpoint(t *testing.T) {
	valid := Checkpoint{
		Name:          "runtime-state",
		ScopeID:       "scope-a",
		Sequence:      1,
		EventID:       1,
		Checksum:      "placeholder",
		State:         json.RawMessage(`{"status":"idle"}`),
		Metadata:      map[string]any{"trigger": "good"},
		SchemaVersion: SchemaVersion,
		CreatedAt:     time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC),
	}
	valid.Checksum = checkpointReplayChecksum(valid.Name, valid.ScopeID, valid.Sequence, valid.EventID, valid.State, valid.Metadata, valid.SchemaVersion, valid.CreatedAt)
	invalid := Checkpoint{
		Name:          "runtime-state",
		ScopeID:       "scope-a",
		Sequence:      2,
		EventID:       2,
		Checksum:      "broken",
		State:         json.RawMessage(`{"status":"executing"}`),
		Metadata:      map[string]any{"trigger": "bad"},
		SchemaVersion: SchemaVersion,
		CreatedAt:     time.Date(2026, 5, 31, 11, 0, 0, 0, time.UTC),
	}
	store := &memoryStore{
		events: []Event{
			{ID: 1, Sequence: 1, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":1}`), Timestamp: time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)},
			{ID: 2, Sequence: 2, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":2}`), Timestamp: time.Date(2026, 5, 31, 11, 0, 0, 0, time.UTC)},
		},
		checkpoints: []Checkpoint{valid, invalid},
	}
	state := &replayState{}
	result, err := ReplayWithOptions(context.Background(), store, "scope-a", state, ReplayOptions{
		CheckpointName: "runtime-state",
	})
	if err != nil {
		t.Fatalf("replay with fallback checkpoint: %v", err)
	}
	if !result.UsedCheckpoint || result.StartedAfterSequence != 1 || result.FinalSequence != 2 {
		t.Fatalf("unexpected replay result: %+v", result)
	}
	if len(state.restored) != 1 || state.restored[0].Sequence != 1 {
		t.Fatalf("expected earlier valid checkpoint to be restored, got %+v", state.restored)
	}
	if len(state.applied) != 1 || state.applied[0] != 2 {
		t.Fatalf("expected replay from sequence 2 only, got %v", state.applied)
	}
}

func TestReplayWithInvalidCheckpointCanStartFromGenesisWhenAllowed(t *testing.T) {
	store := &memoryStore{
		events: []Event{
			{ID: 1, Sequence: 1, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":1}`), Timestamp: time.Now().UTC()},
		},
		checkpoints: []Checkpoint{
			{
				Name:          "runtime-state",
				ScopeID:       "scope-b",
				Sequence:      3,
				EventID:       3,
				Checksum:      "broken",
				State:         json.RawMessage(`{"status":"invalid"}`),
				Metadata:      map[string]any{"trigger": "bad"},
				SchemaVersion: SchemaVersion,
				CreatedAt:     time.Now().UTC(),
			},
		},
	}
	state := &replayState{}
	result, err := ReplayWithOptions(context.Background(), store, "scope-a", state, ReplayOptions{
		CheckpointName:                      "runtime-state",
		AllowGenesisReplayWithoutCheckpoint: true,
	})
	if err != nil {
		t.Fatalf("replay from genesis with invalid checkpoint allowed: %v", err)
	}
	if result.UsedCheckpoint {
		t.Fatalf("expected genesis replay without checkpoint, got %+v", result)
	}
	if len(state.applied) != 1 || state.applied[0] != 1 {
		t.Fatalf("expected genesis replay to apply event 1, got %v", state.applied)
	}
}

func TestReplayAfterCheckpointAwareCompactionMatchesFullReplay(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	checkpoint := Checkpoint{
		Name:          "runtime-state",
		ScopeID:       "scope-a",
		Sequence:      2,
		EventID:       2,
		State:         json.RawMessage(`{"status":"planning"}`),
		Metadata:      map[string]any{"trigger": "checkpoint"},
		SchemaVersion: SchemaVersion,
		CreatedAt:     now,
	}
	checkpoint.Checksum = checkpointReplayChecksum(checkpoint.Name, checkpoint.ScopeID, checkpoint.Sequence, checkpoint.EventID, checkpoint.State, checkpoint.Metadata, checkpoint.SchemaVersion, checkpoint.CreatedAt)

	fullStore := &memoryStore{
		events: []Event{
			{ID: 1, Sequence: 1, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":1}`), Timestamp: now},
			{ID: 2, Sequence: 2, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":2}`), Timestamp: now.Add(time.Second)},
			{ID: 3, Sequence: 3, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":3}`), Timestamp: now.Add(2 * time.Second)},
			{ID: 4, Sequence: 4, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":4}`), Timestamp: now.Add(3 * time.Second)},
		},
		checkpoints: []Checkpoint{checkpoint},
	}
	compactStore := &memoryStore{
		events: []Event{
			{ID: 3, Sequence: 3, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":3}`), Timestamp: now.Add(2 * time.Second)},
			{ID: 4, Sequence: 4, ScopeID: "scope-a", Payload: json.RawMessage(`{"n":4}`), Timestamp: now.Add(3 * time.Second)},
		},
		checkpoints: []Checkpoint{checkpoint},
	}

	fullState := &replayState{}
	fullResult, err := ReplayWithOptions(context.Background(), fullStore, "scope-a", fullState, ReplayOptions{
		CheckpointName: "runtime-state",
	})
	if err != nil {
		t.Fatalf("replay full store: %v", err)
	}

	compactState := &replayState{}
	compactResult, err := ReplayWithOptions(context.Background(), compactStore, "scope-a", compactState, ReplayOptions{
		CheckpointName: "runtime-state",
	})
	if err != nil {
		t.Fatalf("replay compact store: %v", err)
	}

	if !fullResult.UsedCheckpoint || !compactResult.UsedCheckpoint {
		t.Fatalf("expected checkpoint-backed replay on both paths: full=%+v compact=%+v", fullResult, compactResult)
	}
	if fullResult.FinalSequence != compactResult.FinalSequence || fullResult.EventsApplied != compactResult.EventsApplied {
		t.Fatalf("replay diverged after compaction: full=%+v compact=%+v", fullResult, compactResult)
	}
	if len(fullState.applied) != len(compactState.applied) {
		t.Fatalf("applied length mismatch: full=%v compact=%v", fullState.applied, compactState.applied)
	}
	for i := range fullState.applied {
		if fullState.applied[i] != compactState.applied[i] {
			t.Fatalf("applied sequence mismatch at %d: full=%v compact=%v", i, fullState.applied, compactState.applied)
		}
	}
}
