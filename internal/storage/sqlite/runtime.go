package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

type RuntimeRepository struct {
	db *DB
}

func NewRuntimeRepository(db *DB) *RuntimeRepository {
	return &RuntimeRepository{db: db}
}

func (r *RuntimeRepository) Load(ctx context.Context) (models.RuntimeState, error) {
	const op = "storage.sqlite.RuntimeRepository.Load"
	var data string
	err := r.db.Conn().QueryRowContext(ctx, "SELECT data FROM runtime_state WHERE id = 1").Scan(&data)
	if err == sql.ErrNoRows {
		return models.RuntimeState{}, nil
	}
	if err != nil {
		return models.RuntimeState{}, apperr.Wrap(op, err)
	}

	var state models.RuntimeState
	if err := json.Unmarshal([]byte(data), &state); err != nil {
		return models.RuntimeState{}, apperr.Wrap(op, err)
	}
	return state, nil
}

func (r *RuntimeRepository) Save(ctx context.Context, state models.RuntimeState) error {
	const op = "storage.sqlite.RuntimeRepository.Save"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return apperr.Wrap(op, err)
	}

	_, err = r.db.Conn().ExecContext(ctx, `
		INSERT INTO runtime_state (id, data) VALUES (1, ?)
		ON CONFLICT(id) DO UPDATE SET data = excluded.data, updated_at = CURRENT_TIMESTAMP
	`, string(data))
	return apperr.Wrap(op, err)
}
