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

func TestStateStore_ListScopesReturnsScopedStatesOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := NewStateStore(dir)
	if err := store.Save(models.RuntimeState{CurrentEpoch: models.Epoch{Generation: 1}}); err != nil {
		t.Fatalf("save global state: %v", err)
	}
	if err := store.SaveForScope("scope-a", models.RuntimeState{CurrentEpoch: models.Epoch{Generation: 2}}); err != nil {
		t.Fatalf("save scoped state a: %v", err)
	}
	if err := store.SaveForScope("scope-b", models.RuntimeState{CurrentEpoch: models.Epoch{Generation: 3}}); err != nil {
		t.Fatalf("save scoped state b: %v", err)
	}

	scopes, err := store.ListScopes()
	if err != nil {
		t.Fatalf("list scopes: %v", err)
	}
	if len(scopes) != 2 {
		t.Fatalf("expected two scoped states, got %v", scopes)
	}
	seen := map[string]bool{}
	for _, scopeID := range scopes {
		seen[scopeID] = true
	}
	if !seen["scope-a"] || !seen["scope-b"] {
		t.Fatalf("expected scope-a and scope-b, got %v", scopes)
	}
}
