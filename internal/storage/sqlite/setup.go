package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

// SetupStore persists setup wizard progress and named UI settings.
type SetupStore struct {
	db *DB
}

func NewSetupStore(db *DB) *SetupStore {
	return &SetupStore{db: db}
}

// GetCurrentStep returns the current wizard step (1–9). Returns 1 if no row exists.
func (s *SetupStore) GetCurrentStep(ctx context.Context) (int, error) {
	const op = "storage.sqlite.SetupStore.GetCurrentStep"
	var step int
	err := s.db.Conn().QueryRowContext(ctx, `SELECT current_step FROM setup_state WHERE id = 1`).Scan(&step)
	if err == sql.ErrNoRows {
		return 1, nil
	}
	if err != nil {
		return 0, apperr.Wrap(op, err)
	}
	return step, nil
}

// SetCurrentStep persists the current wizard step.
func (s *SetupStore) SetCurrentStep(ctx context.Context, step int) error {
	const op = "storage.sqlite.SetupStore.SetCurrentStep"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx,
		`INSERT INTO setup_state (id, current_step, updated_at)
		 VALUES (1, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET current_step = excluded.current_step, updated_at = excluded.updated_at`,
		step, time.Now().UTC(),
	)
	return apperr.Wrap(op, err)
}

// IsComplete reports whether the setup wizard has been completed.
func (s *SetupStore) IsComplete(ctx context.Context) (bool, error) {
	const op = "storage.sqlite.SetupStore.IsComplete"
	var completedAt sql.NullTime
	err := s.db.Conn().QueryRowContext(ctx, `SELECT completed_at FROM setup_state WHERE id = 1`).Scan(&completedAt)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, apperr.Wrap(op, err)
	}
	return completedAt.Valid, nil
}

// MarkComplete marks setup as complete with the current timestamp.
func (s *SetupStore) MarkComplete(ctx context.Context) error {
	const op = "storage.sqlite.SetupStore.MarkComplete"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err := s.db.Conn().ExecContext(ctx,
		`INSERT INTO setup_state (id, current_step, completed_at, updated_at)
		 VALUES (1, 9, ?, ?)
		 ON CONFLICT(id) DO UPDATE SET current_step = excluded.current_step, completed_at = excluded.completed_at, updated_at = excluded.updated_at`,
		now, now,
	)
	return apperr.Wrap(op, err)
}

// GetSetting retrieves a named setting value. Returns ("", false, nil) when not set.
func (s *SetupStore) GetSetting(ctx context.Context, key string) (string, bool, error) {
	const op = "storage.sqlite.SetupStore.GetSetting"
	var val string
	err := s.db.Conn().QueryRowContext(ctx, `SELECT value FROM ui_settings WHERE key = ?`, key).Scan(&val)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, apperr.Wrap(op, err)
	}
	return val, true, nil
}

// SetSetting upserts a named setting.
func (s *SetupStore) SetSetting(ctx context.Context, key, value string) error {
	const op = "storage.sqlite.SetupStore.SetSetting"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx,
		`INSERT INTO ui_settings (key, value, updated_at) VALUES (?, ?, ?)
		 ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at`,
		key, value, time.Now().UTC(),
	)
	return apperr.Wrap(op, err)
}
