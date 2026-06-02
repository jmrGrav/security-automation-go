package drift

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

func TestEnginePromotesRepeatedConvergenceDriftToOscillation(t *testing.T) {
	t.Parallel()

	store := state.NewStateStore(t.TempDir())
	sm := engine.NewStateMachine(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	eng := NewEngine(resources.NewRegistry(), sm, memory.NewStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	var decision EscalationDecision
	var event DriftEvent
	for i := 0; i < 6; i++ {
		event = DriftEvent{
			ID:          "drift-1",
			Fingerprint: "same-convergence-drift",
			Diff:        "convergence mismatch after apply",
		}
		decision = eng.Process(context.Background(), &event, "scope-a", "leader-a")
	}

	if event.Classification != ClassOscillation {
		t.Fatalf("expected repeated convergence drift to become oscillation, got %s", event.Classification)
	}
	if event.RiskLevel != LevelHigh {
		t.Fatalf("expected oscillation risk high, got %s", event.RiskLevel)
	}
	if decision.Action != ActionCooldown {
		t.Fatalf("expected oscillation to trigger cooldown, got %s", decision.Action)
	}
}

func TestHostileDriftQuarantinesStateMachine(t *testing.T) {
	t.Parallel()

	store := state.NewStateStore(t.TempDir())
	sm := engine.NewStateMachine(store, slog.New(slog.NewTextHandler(io.Discard, nil)))
	eng := NewEngine(resources.NewRegistry(), sm, memory.NewStore(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	event := DriftEvent{
		ID:          "drift-hostile",
		Fingerprint: "deleted-rule",
		Diff:        "rule deleted remotely",
	}
	decision := eng.Process(context.Background(), &event, "scope-a", "leader-a")
	if decision.Action != ActionQuarantine {
		t.Fatalf("expected hostile drift quarantine, got %s", decision.Action)
	}

	got, err := store.Load()
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if got.Lifecycle.Status != models.StatusQuarantined {
		t.Fatalf("expected state machine quarantined, got %s", got.Lifecycle.Status)
	}
}
