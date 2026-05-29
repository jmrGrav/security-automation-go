package sqlite

import (
	"context"
	"database/sql"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

type CursorStore struct {
	db *DB
}

func NewCursorStore(db *DB) *CursorStore {
	return &CursorStore{db: db}
}

func (s *CursorStore) Load(ctx context.Context, name string) (time.Time, bool, error) {
	const op = "storage.sqlite.CursorStore.Load"
	var raw string
	err := s.db.Conn().QueryRowContext(ctx, "SELECT cursor_value FROM runtime_cursors WHERE name = ?", name).Scan(&raw)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, apperr.Wrap(op, err)
	}
	parsed, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, false, apperr.Wrap(op, err)
	}
	return parsed.UTC(), true, nil
}

func (s *CursorStore) Save(ctx context.Context, name string, value time.Time) error {
	const op = "storage.sqlite.CursorStore.Save"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	if value.IsZero() {
		value = time.Now().UTC()
	}
	_, err := s.db.Conn().ExecContext(ctx, `
		INSERT INTO runtime_cursors (name, cursor_value, updated_at)
		VALUES (?, ?, ?)
		ON CONFLICT(name) DO UPDATE SET
			cursor_value = excluded.cursor_value,
			updated_at = excluded.updated_at
	`, name, value.UTC().Format(time.RFC3339Nano), time.Now().UTC())
	return apperr.Wrap(op, err)
}
