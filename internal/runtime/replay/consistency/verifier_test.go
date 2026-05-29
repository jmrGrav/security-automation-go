package consistency

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
)

type store struct {
	events      []events.Event
	checkpoints []events.Checkpoint
}

func (s store) List(_ context.Context, scopeID string, afterSequence uint64) ([]events.Event, error) {
	var out []events.Event
	for _, event := range s.events {
		if event.ScopeID == scopeID && event.Sequence > afterSequence {
			out = append(out, event)
		}
	}
	return out, nil
}

func (s store) ListCheckpoints(_ context.Context, scopeID string, name string, limit int) ([]events.Checkpoint, error) {
	var out []events.Checkpoint
	for _, cp := range s.checkpoints {
		if cp.ScopeID == scopeID && cp.Name == name {
			out = append(out, cp)
		}
	}
	return out, nil
}

func TestVerifierDetectsHealthyReplayChain(t *testing.T) {
	now := time.Now().UTC()
	s := store{
		events: []events.Event{
			{ScopeID: "scope-a", Sequence: 1, Timestamp: now, Category: events.CategoryLifecycle, Type: events.TypeLifecycleTransition, Payload: json.RawMessage(`{}`)},
			{ScopeID: "scope-a", Sequence: 2, Timestamp: now.Add(time.Second), Category: events.CategoryLifecycle, Type: events.TypeLifecycleTransition, Payload: json.RawMessage(`{}`)},
		},
		checkpoints: []events.Checkpoint{{Name: "runtime-state", ScopeID: "scope-a", Sequence: 2}},
	}
	report, err := NewVerifier(s, s).Verify(context.Background(), "scope-a", "runtime-state")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.ContinuityOK || !report.OrderingOK || !report.CheckpointsValid || report.DivergenceDetected {
		t.Fatalf("unexpected report: %+v", report)
	}
}

func TestVerifierDetectsSequenceGap(t *testing.T) {
	now := time.Now().UTC()
	s := store{
		events: []events.Event{
			{ScopeID: "scope-a", Sequence: 1, Timestamp: now, Payload: json.RawMessage(`{}`)},
			{ScopeID: "scope-a", Sequence: 3, Timestamp: now.Add(time.Second), Payload: json.RawMessage(`{}`)},
		},
	}
	report, err := NewVerifier(s, nil).Verify(context.Background(), "scope-a", "runtime-state")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if report.ContinuityOK || !report.DivergenceDetected {
		t.Fatalf("expected gap divergence, got %+v", report)
	}
}
