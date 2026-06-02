package sqlite

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

func TestRuntimeRepositorySaveLoad(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := NewRuntimeRepository(db)
	want := models.RuntimeState{
		LastRunID: "run-1",
		Lifecycle: models.LifecycleState{
			Status: models.StatusConverged,
		},
	}
	if err := repo.Save(context.Background(), want); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := repo.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.LastRunID != want.LastRunID || got.Lifecycle.Status != want.Lifecycle.Status {
		t.Fatalf("unexpected state: %+v", got)
	}
}

func TestRuntimeRepositoryLoadEmptyReturnsZeroState(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := NewRuntimeRepository(db)
	got, err := repo.Load(context.Background())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.LastRunID != "" || got.Lifecycle.Status != "" {
		t.Fatalf("expected zero state, got %+v", got)
	}
}
