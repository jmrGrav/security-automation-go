package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/enforcementlog"
)

// EnforcementEventStore is the SQLite-backed implementation of
// enforcementlog.Store. It is an append-only log: every row is a single
// Cloudflare ban or deban attempt, success or failure.
type EnforcementEventStore struct {
	db *DB
}

// NewEnforcementEventStore returns an EnforcementEventStore backed by db.
func NewEnforcementEventStore(db *DB) *EnforcementEventStore {
	return &EnforcementEventStore{db: db}
}

var _ enforcementlog.Store = (*EnforcementEventStore)(nil)

// Append inserts e as a new row. Never updates or deletes existing rows.
func (s *EnforcementEventStore) Append(ctx context.Context, e enforcementlog.Event) error {
	const op = "storage.sqlite.EnforcementEventStore.Append"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	if e.OccurredAt.IsZero() {
		e.OccurredAt = time.Now().UTC()
	}
	_, err := s.db.Conn().ExecContext(ctx, `
		INSERT INTO cf_enforcement_events (
			occurred_at, action, ip, reason, rule_id, success, error, duration_ns
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, e.OccurredAt.UTC(), e.Action, e.IP, e.Reason, e.RuleID, boolToInt(e.Success), e.Error, int64(e.Duration))
	return apperr.Wrap(op, err)
}

// Recent returns the most recent events, newest first, capped at limit.
func (s *EnforcementEventStore) Recent(ctx context.Context, limit int) ([]enforcementlog.Event, error) {
	const op = "storage.sqlite.EnforcementEventStore.Recent"
	if limit <= 0 {
		limit = 100
	}
	rows, err := s.db.Conn().QueryContext(ctx, `
		SELECT id, occurred_at, action, ip, reason, rule_id, success, error, duration_ns
		FROM cf_enforcement_events
		ORDER BY occurred_at DESC, id DESC
		LIMIT ?
	`, limit)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()
	return scanEnforcementEvents(op, rows)
}

// LastSuccess returns the most recent successful event, if any.
func (s *EnforcementEventStore) LastSuccess(ctx context.Context) (enforcementlog.Event, bool, error) {
	return s.lastWhere(ctx, "storage.sqlite.EnforcementEventStore.LastSuccess", true)
}

// LastFailure returns the most recent failed event, if any.
func (s *EnforcementEventStore) LastFailure(ctx context.Context) (enforcementlog.Event, bool, error) {
	return s.lastWhere(ctx, "storage.sqlite.EnforcementEventStore.LastFailure", false)
}

func (s *EnforcementEventStore) lastWhere(ctx context.Context, op string, success bool) (enforcementlog.Event, bool, error) {
	row := s.db.Conn().QueryRowContext(ctx, `
		SELECT id, occurred_at, action, ip, reason, rule_id, success, error, duration_ns
		FROM cf_enforcement_events
		WHERE success = ?
		ORDER BY occurred_at DESC, id DESC
		LIMIT 1
	`, boolToInt(success))
	e, err := scanEnforcementEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return enforcementlog.Event{}, false, nil
	}
	if err != nil {
		return enforcementlog.Event{}, false, apperr.Wrap(op, err)
	}
	return e, true, nil
}

func scanEnforcementEvent(row *sql.Row) (enforcementlog.Event, error) {
	var e enforcementlog.Event
	var durationNS int64
	var occurredAt time.Time
	var success int
	if err := row.Scan(&e.ID, &occurredAt, &e.Action, &e.IP, &e.Reason, &e.RuleID, &success, &e.Error, &durationNS); err != nil {
		return enforcementlog.Event{}, err
	}
	e.OccurredAt = occurredAt.UTC()
	e.Duration = time.Duration(durationNS)
	e.Success = success != 0
	return e, nil
}

func scanEnforcementEvents(op string, rows *sql.Rows) ([]enforcementlog.Event, error) {
	var out []enforcementlog.Event
	for rows.Next() {
		var e enforcementlog.Event
		var durationNS int64
		var occurredAt time.Time
		var success int
		if err := rows.Scan(&e.ID, &occurredAt, &e.Action, &e.IP, &e.Reason, &e.RuleID, &success, &e.Error, &durationNS); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		e.OccurredAt = occurredAt.UTC()
		e.Duration = time.Duration(durationNS)
		e.Success = success != 0
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return out, nil
}
