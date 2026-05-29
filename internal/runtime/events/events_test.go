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
				Checksum:      "sha256:test",
				State:         json.RawMessage(`{"status":"planning"}`),
				SchemaVersion: SchemaVersion,
				CreatedAt:     time.Now().UTC(),
			},
		},
	}
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
