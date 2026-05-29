package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/events"
)

type EventRepository struct {
	db     *DB
	commit func(*sql.Tx) error
}

func NewEventRepository(db *DB) *EventRepository {
	return &EventRepository{db: db, commit: func(tx *sql.Tx) error { return tx.Commit() }}
}

var ErrCommitAmbiguous = errors.New("sqlite event append commit ambiguous")

func (r *EventRepository) Append(ctx context.Context, event *events.Event) error {
	const op = "storage.sqlite.EventRepository.Append"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}
	if event.UID == "" {
		event.UID = eventUID(*event)
	}
	if ok, err := r.loadExistingEvent(ctx, event); err != nil {
		return apperr.Wrap(op, err)
	} else if ok {
		return nil
	}

	metadata, err := json.Marshal(event.Metadata)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	for attempt := 0; attempt < 5; attempt++ {
		tx, err := r.db.Conn().BeginTx(ctx, nil)
		if err != nil {
			if isSQLiteBusy(err) && attempt < 4 {
				time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
				continue
			}
			return apperr.Wrap(op, err)
		}

		var nextSeq uint64
		err = tx.QueryRowContext(ctx, `
			INSERT INTO event_sequences(scope_id, next_sequence)
			VALUES (?, 2)
			ON CONFLICT(scope_id) DO UPDATE SET next_sequence = event_sequences.next_sequence + 1
			RETURNING next_sequence - 1
		`, event.ScopeID).Scan(&nextSeq)
		if err != nil {
			_ = tx.Rollback()
			if isSQLiteBusy(err) && attempt < 4 {
				time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
				continue
			}
			return apperr.Wrap(op, err)
		}
		event.Sequence = nextSeq

		res, err := tx.ExecContext(ctx, `
			INSERT INTO events (
				sequence, timestamp, category, type, correlation_id, 
				causal_id, actor, scope_id, payload, metadata, event_uid
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, event.Sequence, event.Timestamp, event.Category, event.Type,
			event.CorrelationID, event.CausalID, event.Actor, event.ScopeID,
			string(event.Payload), string(metadata), event.UID)
		if err != nil {
			_ = tx.Rollback()
			if isSQLiteConstraint(err) {
				if ok, lookupErr := r.loadExistingEvent(ctx, event); lookupErr == nil && ok {
					return nil
				}
			}
			if isSQLiteBusy(err) && attempt < 4 {
				time.Sleep(time.Duration(attempt+1) * 10 * time.Millisecond)
				continue
			}
			return apperr.Wrap(op, err)
		}

		id, err := res.LastInsertId()
		if err != nil {
			_ = tx.Rollback()
			return apperr.Wrap(op, err)
		}
		event.ID = id

		if err := r.commit(tx); err != nil {
			if ok, lookupErr := r.loadExistingEvent(ctx, event); lookupErr == nil && ok {
				return nil
			}
			return apperr.Wrap(op, fmt.Errorf("%w: %v", ErrCommitAmbiguous, err))
		}
		return nil
	}

	return apperr.New(op, "failed to append event after retry budget")
}

func (r *EventRepository) List(ctx context.Context, scopeID string, afterSequence uint64) ([]events.Event, error) {
	const op = "storage.sqlite.EventRepository.List"

	rows, err := r.db.Conn().QueryContext(ctx, `
		SELECT id, sequence, event_uid, timestamp, category, type, correlation_id, 
		       causal_id, actor, scope_id, payload, metadata
		FROM events
		WHERE scope_id = ? AND sequence > ?
		ORDER BY sequence ASC
	`, scopeID, afterSequence)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()

	var evs []events.Event
	for rows.Next() {
		var ev events.Event
		var payload, metadata string
		err := rows.Scan(
			&ev.ID, &ev.Sequence, &ev.UID, &ev.Timestamp, &ev.Category, &ev.Type,
			&ev.CorrelationID, &ev.CausalID, &ev.Actor, &ev.ScopeID,
			&payload, &metadata,
		)
		if err != nil {
			return nil, apperr.Wrap(op, err)
		}
		ev.Payload = json.RawMessage(payload)
		if metadata != "" {
			if err := json.Unmarshal([]byte(metadata), &ev.Metadata); err != nil {
				return nil, apperr.Wrap(op, err)
			}
		}
		evs = append(evs, ev)
	}

	return evs, rows.Err()
}

func (r *EventRepository) loadExistingEvent(ctx context.Context, event *events.Event) (bool, error) {
	if r == nil || event == nil || event.UID == "" || event.ScopeID == "" {
		return false, nil
	}
	row := r.db.Conn().QueryRowContext(ctx, `
		SELECT id, sequence
		FROM events
		WHERE scope_id = ? AND event_uid = ?
	`, event.ScopeID, event.UID)
	if err := row.Scan(&event.ID, &event.Sequence); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func eventUID(event events.Event) string {
	payload, _ := json.Marshal(struct {
		Timestamp     string          `json:"timestamp"`
		Category      events.Category `json:"category"`
		Type          string          `json:"type"`
		CorrelationID string          `json:"correlation_id"`
		CausalID      string          `json:"causal_id"`
		Actor         string          `json:"actor"`
		ScopeID       string          `json:"scope_id"`
		Payload       json.RawMessage `json:"payload"`
		Metadata      map[string]any  `json:"metadata,omitempty"`
	}{
		Timestamp:     event.Timestamp.UTC().Format(time.RFC3339Nano),
		Category:      event.Category,
		Type:          event.Type,
		CorrelationID: event.CorrelationID,
		CausalID:      event.CausalID,
		Actor:         event.Actor,
		ScopeID:       event.ScopeID,
		Payload:       event.Payload,
		Metadata:      event.Metadata,
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (r *EventRepository) GetLastSequence(ctx context.Context, scopeID string) (uint64, error) {
	const op = "storage.sqlite.EventRepository.GetLastSequence"
	var seq uint64
	err := r.db.Conn().QueryRowContext(ctx, "SELECT COALESCE(MAX(sequence), 0) FROM events WHERE scope_id = ?", scopeID).Scan(&seq)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	return seq, apperr.Wrap(op, err)
}

func (r *EventRepository) SaveCheckpoint(ctx context.Context, checkpoint events.Checkpoint) error {
	const op = "storage.sqlite.EventRepository.SaveCheckpoint"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}

	metadata, err := json.Marshal(checkpoint.Metadata)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if checkpoint.SchemaVersion == 0 {
		checkpoint.SchemaVersion = events.SchemaVersion
	}
	if checkpoint.CreatedAt.IsZero() {
		checkpoint.CreatedAt = time.Now().UTC()
	}

	_, err = r.db.Conn().ExecContext(ctx, `
		INSERT INTO event_checkpoints (
			name, scope_id, sequence, event_id, checksum, state, metadata, schema_version, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, checkpoint.Name, checkpoint.ScopeID, checkpoint.Sequence, checkpoint.EventID, checkpoint.Checksum, string(checkpoint.State), string(metadata), checkpoint.SchemaVersion, checkpoint.CreatedAt)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	return nil
}

func (r *EventRepository) LatestCheckpoint(ctx context.Context, scopeID string, name string) (events.Checkpoint, error) {
	const op = "storage.sqlite.EventRepository.LatestCheckpoint"

	var checkpoint events.Checkpoint
	var state string
	var metadata string
	err := r.db.Conn().QueryRowContext(ctx, `
		SELECT name, scope_id, sequence, event_id, checksum, state, metadata, schema_version, created_at
		FROM event_checkpoints
		WHERE scope_id = ? AND name = ?
		ORDER BY sequence DESC
		LIMIT 1
	`, scopeID, name).Scan(
		&checkpoint.Name,
		&checkpoint.ScopeID,
		&checkpoint.Sequence,
		&checkpoint.EventID,
		&checkpoint.Checksum,
		&state,
		&metadata,
		&checkpoint.SchemaVersion,
		&checkpoint.CreatedAt,
	)
	if err == sql.ErrNoRows {
		return events.Checkpoint{}, events.ErrCheckpointNotFound
	}
	if err != nil {
		return events.Checkpoint{}, apperr.Wrap(op, err)
	}

	checkpoint.State = json.RawMessage(state)
	if metadata != "" && metadata != "null" {
		if err := json.Unmarshal([]byte(metadata), &checkpoint.Metadata); err != nil {
			return events.Checkpoint{}, apperr.Wrap(op, err)
		}
	}
	return checkpoint, nil
}

func (r *EventRepository) ListCheckpoints(ctx context.Context, scopeID string, name string, limit int) ([]events.Checkpoint, error) {
	const op = "storage.sqlite.EventRepository.ListCheckpoints"

	query := `
		SELECT name, scope_id, sequence, event_id, checksum, state, metadata, schema_version, created_at
		FROM event_checkpoints
		WHERE scope_id = ? AND name = ?
		ORDER BY sequence DESC
	`
	args := []any{scopeID, name}
	if limit > 0 {
		query += " LIMIT ?"
		args = append(args, limit)
	}

	rows, err := r.db.Conn().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()

	var checkpoints []events.Checkpoint
	for rows.Next() {
		var checkpoint events.Checkpoint
		var state string
		var metadata string
		if err := rows.Scan(
			&checkpoint.Name,
			&checkpoint.ScopeID,
			&checkpoint.Sequence,
			&checkpoint.EventID,
			&checkpoint.Checksum,
			&state,
			&metadata,
			&checkpoint.SchemaVersion,
			&checkpoint.CreatedAt,
		); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		checkpoint.State = json.RawMessage(state)
		if metadata != "" && metadata != "null" {
			if err := json.Unmarshal([]byte(metadata), &checkpoint.Metadata); err != nil {
				return nil, apperr.Wrap(op, err)
			}
		}
		checkpoints = append(checkpoints, checkpoint)
	}
	return checkpoints, rows.Err()
}

func (r *EventRepository) DeleteCheckpoint(ctx context.Context, scopeID string, name string, sequence uint64) error {
	const op = "storage.sqlite.EventRepository.DeleteCheckpoint"
	if err := r.db.ensureWritable(op); err != nil {
		return err
	}
	_, err := r.db.Conn().ExecContext(ctx, `
		DELETE FROM event_checkpoints
		WHERE scope_id = ? AND name = ? AND sequence = ?
	`, scopeID, name, sequence)
	return apperr.Wrap(op, err)
}
