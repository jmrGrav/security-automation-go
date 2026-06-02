package timeline

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
)

type fakeTimelineStore struct {
	events []events.Event
}

func (s fakeTimelineStore) List(_ context.Context, _ string, _ uint64) ([]events.Event, error) {
	return append([]events.Event(nil), s.events...), nil
}

func (s fakeTimelineStore) Append(context.Context, *events.Event) error { return nil }
func (s fakeTimelineStore) GetLastSequence(context.Context, string) (uint64, error) {
	return 0, nil
}

func TestCollectorCapsOutput(t *testing.T) {
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	store := fakeTimelineStore{events: []events.Event{
		{Sequence: 1, Timestamp: base, Category: events.CategoryLifecycle, Type: "one", Actor: "a", CorrelationID: "c1"},
		{Sequence: 2, Timestamp: base.Add(time.Minute), Category: events.CategoryLifecycle, Type: "two", Actor: "a", CorrelationID: "c2"},
		{Sequence: 3, Timestamp: base.Add(2 * time.Minute), Category: events.CategoryLifecycle, Type: "three", Actor: "a", CorrelationID: "c3"},
	}}

	collector := NewCollectorWithLimit(store, 2)
	got, err := collector.Assemble(context.Background(), "scope-1")
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected capped timeline output, got %d", len(got))
	}
	if got[0].Sequence != 2 || got[1].Sequence != 3 {
		t.Fatalf("expected the most recent entries, got %+v", got)
	}
}
