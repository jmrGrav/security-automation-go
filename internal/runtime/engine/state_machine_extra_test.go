package engine_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

type fakeEventBus struct {
	event events.Event
	err   error
}

func (f *fakeEventBus) PublishEvent(_ context.Context, req events.PublishRequest) (events.Event, error) {
	if f.err != nil {
		return events.Event{}, f.err
	}
	f.event = events.Event{
		Sequence:      1,
		ScopeID:       req.ScopeID,
		CorrelationID: req.CorrelationID,
		Actor:         req.Actor,
		Type:          req.Type,
		Category:      req.Category,
	}
	return f.event, nil
}

type fakeCheckpointManager struct {
	runtimeCalls int
	namedCalls   int
	err          error
}

func (f *fakeCheckpointManager) SaveRuntimeState(_ context.Context, _ string, _ string, _ events.Event, _ models.RuntimeState) (events.Checkpoint, error) {
	f.runtimeCalls++
	if f.err != nil {
		return events.Checkpoint{}, f.err
	}
	return events.Checkpoint{Name: "runtime"}, nil
}

func (f *fakeCheckpointManager) SaveNamedRuntimeState(_ context.Context, _ string, _ string, _ string, _ events.Event, _ models.RuntimeState) (events.Checkpoint, error) {
	f.namedCalls++
	if f.err != nil {
		return events.Checkpoint{}, f.err
	}
	return events.Checkpoint{Name: "named"}, nil
}

func TestStateMachine_UsesEventBusAndCheckpoints(t *testing.T) {
	dir := t.TempDir()
	store := state.NewStateStore(dir)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	sm := engine.NewStateMachine(store, logger)

	bus := &fakeEventBus{}
	cps := &fakeCheckpointManager{}
	sm.SetEventBus(bus)
	sm.SetCheckpointManager(cps)

	if err := sm.Transition(context.Background(), models.StatusDiscovering, "start"); err != nil {
		t.Fatalf("transition: %v", err)
	}
	if bus.event.Type != events.TypeLifecycleTransition {
		t.Fatalf("expected lifecycle event, got %+v", bus.event)
	}
	if cps.runtimeCalls != 1 {
		t.Fatalf("expected one runtime checkpoint, got %d", cps.runtimeCalls)
	}
}
