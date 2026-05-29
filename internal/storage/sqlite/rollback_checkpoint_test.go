package sqlite

import (
	"context"
	"testing"
	"time"

	rollbackmodels "github.com/jm/security-automation-go/internal/rollback/models"
)

func TestRollbackCheckpointStoreSaveLoad(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewRollbackCheckpointStore(db)
	batch := rollbackmodels.RollbackBatch{
		ID:                 "rb-1",
		OriginatingBatchID: "batch-a",
		Status:             rollbackmodels.StateExecuting,
		LastCompletedOpIdx: 2,
		StartedAt:          time.Now().UTC().Add(-time.Minute).Round(time.Second),
		Operations: []rollbackmodels.CompensationOperation{
			{OperationID: "op-1", ScopeID: "scope-a", ResourceType: "ip_access_rules"},
			{OperationID: "op-2", ScopeID: "scope-a", ResourceType: "ip_access_rules"},
		},
	}
	if err := store.SaveRollbackCheckpoint(context.Background(), batch); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}
	got, ok, err := store.LoadRollbackCheckpoint(context.Background(), "rb-1")
	if err != nil || !ok {
		t.Fatalf("load checkpoint err=%v ok=%v", err, ok)
	}
	if got.ID != batch.ID || got.LastCompletedOpIdx != 2 || got.Status != rollbackmodels.StateExecuting {
		t.Fatalf("unexpected checkpoint payload: %+v", got)
	}

	batch.Status = rollbackmodels.StateCompleted
	batch.LastCompletedOpIdx = 2
	batch.FinishedAt = time.Now().UTC().Round(time.Second)
	if err := store.SaveRollbackCheckpoint(context.Background(), batch); err != nil {
		t.Fatalf("save completed checkpoint: %v", err)
	}
	got, ok, err = store.LoadRollbackCheckpoint(context.Background(), "rb-1")
	if err != nil || !ok {
		t.Fatalf("reload checkpoint err=%v ok=%v", err, ok)
	}
	if got.Status != rollbackmodels.StateCompleted || got.FinishedAt.IsZero() {
		t.Fatalf("expected completed checkpoint with finished_at, got %+v", got)
	}
}
