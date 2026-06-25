package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

// Note is an operator annotation attached to a named entity (e.g. an IP address).
type Note struct {
	ID          int64
	EntityType  string
	EntityValue string
	Content     string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// NoteStore persists operator annotations in SQLite.
// Notes are keyed by (entity_type, entity_value) and never influence provider decisions.
type NoteStore struct {
	db *DB
}

// NewNoteStore returns a NoteStore backed by db and ensures the schema exists.
func NewNoteStore(db *DB) (*NoteStore, error) {
	const op = "storage.sqlite.NoteStore.init"
	_, err := db.Conn().Exec(`
		CREATE TABLE IF NOT EXISTS operator_notes (
			id           INTEGER PRIMARY KEY AUTOINCREMENT,
			entity_type  TEXT NOT NULL,
			entity_value TEXT NOT NULL,
			content      TEXT NOT NULL DEFAULT '',
			created_at   DATETIME NOT NULL,
			updated_at   DATETIME NOT NULL,
			UNIQUE(entity_type, entity_value)
		)
	`)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return &NoteStore{db: db}, nil
}

// Upsert creates or replaces the note for the given entity.
func (s *NoteStore) Upsert(ctx context.Context, entityType, entityValue, content string) error {
	const op = "storage.sqlite.NoteStore.Upsert"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	now := time.Now().UTC()
	_, err := s.db.Conn().ExecContext(ctx, `
		INSERT INTO operator_notes (entity_type, entity_value, content, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(entity_type, entity_value) DO UPDATE SET
			content    = excluded.content,
			updated_at = excluded.updated_at
	`, entityType, entityValue, content, now, now)
	return apperr.Wrap(op, err)
}

// Get returns the note for the given entity. ok is false (and err is nil) if no note exists.
func (s *NoteStore) Get(ctx context.Context, entityType, entityValue string) (Note, bool, error) {
	const op = "storage.sqlite.NoteStore.Get"
	var n Note
	err := s.db.Conn().QueryRowContext(ctx, `
		SELECT id, entity_type, entity_value, content, created_at, updated_at
		FROM operator_notes
		WHERE entity_type = ? AND entity_value = ?
	`, entityType, entityValue).Scan(&n.ID, &n.EntityType, &n.EntityValue, &n.Content, &n.CreatedAt, &n.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Note{}, false, nil
	}
	if err != nil {
		return Note{}, false, apperr.Wrap(op, err)
	}
	return n, true, nil
}

// Delete removes the note for the given entity. It is not an error if no note exists.
func (s *NoteStore) Delete(ctx context.Context, entityType, entityValue string) error {
	const op = "storage.sqlite.NoteStore.Delete"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := s.db.Conn().ExecContext(ctx, `
		DELETE FROM operator_notes WHERE entity_type = ? AND entity_value = ?
	`, entityType, entityValue)
	return apperr.Wrap(op, err)
}

// List returns all notes ordered by updated_at descending.
func (s *NoteStore) List(ctx context.Context) ([]Note, error) {
	const op = "storage.sqlite.NoteStore.List"
	rows, err := s.db.Conn().QueryContext(ctx, `
		SELECT id, entity_type, entity_value, content, created_at, updated_at
		FROM operator_notes
		ORDER BY updated_at DESC, id DESC
	`)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()
	var out []Note
	for rows.Next() {
		var n Note
		if err := rows.Scan(&n.ID, &n.EntityType, &n.EntityValue, &n.Content, &n.CreatedAt, &n.UpdatedAt); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		out = append(out, n)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return out, nil
}
