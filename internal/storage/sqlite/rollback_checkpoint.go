package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	rollbackmodels "github.com/jm/security-automation-go/internal/rollback/models"
)

type RollbackCheckpointStore struct {
	db *DB
}

func NewRollbackCheckpointStore(db *DB) *RollbackCheckpointStore {
	return &RollbackCheckpointStore{db: db}
}

func (s *RollbackCheckpointStore) SaveRollbackCheckpoint(ctx context.Context, batch rollbackmodels.RollbackBatch) error {
	const op = "storage.sqlite.RollbackCheckpointStore.SaveRollbackCheckpoint"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	data, err := json.Marshal(batch)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	scopeID := rollbackScopeID(batch)
	_, err = s.db.Conn().ExecContext(ctx, `
		INSERT INTO rollback_checkpoints (
			batch_id, scope_id, status, last_completed_op_idx, started_at, finished_at, data, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(batch_id) DO UPDATE SET
			scope_id = excluded.scope_id,
			status = excluded.status,
			last_completed_op_idx = excluded.last_completed_op_idx,
			started_at = excluded.started_at,
			finished_at = excluded.finished_at,
			data = excluded.data,
			updated_at = CURRENT_TIMESTAMP
	`, batch.ID, scopeID, string(batch.Status), batch.LastCompletedOpIdx, nullTime(batch.StartedAt), nullTime(batch.FinishedAt), string(data))
	return apperr.Wrap(op, err)
}

func (s *RollbackCheckpointStore) LoadRollbackCheckpoint(ctx context.Context, batchID string) (rollbackmodels.RollbackBatch, bool, error) {
	const op = "storage.sqlite.RollbackCheckpointStore.LoadRollbackCheckpoint"
	var data string
	err := s.db.Conn().QueryRowContext(ctx, `
		SELECT data
		FROM rollback_checkpoints
		WHERE batch_id = ?
	`, batchID).Scan(&data)
	if err == sql.ErrNoRows {
		return rollbackmodels.RollbackBatch{}, false, nil
	}
	if err != nil {
		return rollbackmodels.RollbackBatch{}, false, apperr.Wrap(op, err)
	}
	var batch rollbackmodels.RollbackBatch
	if err := json.Unmarshal([]byte(data), &batch); err != nil {
		return rollbackmodels.RollbackBatch{}, false, apperr.Wrap(op, err)
	}
	return batch, true, nil
}

func rollbackScopeID(batch rollbackmodels.RollbackBatch) string {
	for _, op := range batch.Operations {
		if op.ScopeID != "" {
			return op.ScopeID
		}
	}
	return ""
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}
