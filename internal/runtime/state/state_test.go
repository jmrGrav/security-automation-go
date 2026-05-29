package state

import (
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

func TestStateStore_LoadForScope_FallbackToGlobal(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewStateStore(dir)
	global := models.RuntimeState{CurrentEpoch: models.Epoch{Generation: 7}}
	if err := store.Save(global); err != nil {
		t.Fatalf("save global state: %v", err)
	}

	got, err := store.LoadForScope("scope-a")
	if err != nil {
		t.Fatalf("load for scope: %v", err)
	}
	if got.CurrentEpoch.Generation != 7 {
		t.Fatalf("expected fallback global generation=7, got %d", got.CurrentEpoch.Generation)
	}
}

func TestStateStore_LoadForScope_UsesScopedStateWhenPresent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewStateStore(dir)
	global := models.RuntimeState{CurrentEpoch: models.Epoch{Generation: 7}}
	scoped := models.RuntimeState{CurrentEpoch: models.Epoch{Generation: 42}}
	if err := store.Save(global); err != nil {
		t.Fatalf("save global state: %v", err)
	}
	if err := store.SaveForScope("scope-a", scoped); err != nil {
		t.Fatalf("save scoped state: %v", err)
	}

	got, err := store.LoadForScope("scope-a")
	if err != nil {
		t.Fatalf("load for scope: %v", err)
	}
	if got.CurrentEpoch.Generation != 42 {
		t.Fatalf("expected scoped generation=42, got %d", got.CurrentEpoch.Generation)
	}
}
