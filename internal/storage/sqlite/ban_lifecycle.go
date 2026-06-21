package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
)

// BanLifecycleStore is the SQLite-backed implementation of
// banlifecycle.Store. It keeps one row per ban attempt (full history),
// enforcing at most one active row per IP via a partial unique index, so
// RecidiveLevel can count completed (non-active) prior bans.
type BanLifecycleStore struct {
	db *DB
}

// NewBanLifecycleStore returns a BanLifecycleStore backed by db.
func NewBanLifecycleStore(db *DB) *BanLifecycleStore {
	return &BanLifecycleStore{db: db}
}

var _ banlifecycle.Store = (*BanLifecycleStore)(nil)

// Upsert inserts a new active entry for e.IP, or — if an active entry
// already exists for that IP — updates it in place. Re-banning an IP that
// already has a completed (non-active) history is additive: the prior rows
// are preserved so RecidiveLevel can count them.
func (s *BanLifecycleStore) Upsert(ctx context.Context, e banlifecycle.Entry) error {
	const op = "storage.sqlite.BanLifecycleStore.Upsert"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	if e.Status == "" {
		e.Status = banlifecycle.StatusActive
	}
	if e.CreatedAt.IsZero() {
		e.CreatedAt = time.Now().UTC()
	}

	var existingID int64
	err := s.db.Conn().QueryRowContext(ctx, `
		SELECT id FROM cf_ban_lifecycle WHERE ip = ? AND status = ?
	`, e.IP, banlifecycle.StatusActive).Scan(&existingID)
	switch {
	case err == nil:
		_, err = s.db.Conn().ExecContext(ctx, `
			UPDATE cf_ban_lifecycle SET
				source = ?, reason = ?, confidence = ?, created_at = ?, expires_at = ?,
				duration_ns = ?, rule_id = ?, evidence_id = ?, recidive_level = ?,
				status = ?, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?
		`, e.Source, e.Reason, e.Confidence, e.CreatedAt.UTC(), e.ExpiresAt.UTC(),
			int64(e.Duration), e.RuleID, e.EvidenceID, e.RecidiveLevel, e.Status, existingID)
		return apperr.Wrap(op, err)
	case errors.Is(err, sql.ErrNoRows):
		_, err = s.db.Conn().ExecContext(ctx, `
			INSERT INTO cf_ban_lifecycle (
				ip, source, reason, confidence, created_at, expires_at,
				duration_ns, rule_id, evidence_id, recidive_level, status
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`, e.IP, e.Source, e.Reason, e.Confidence, e.CreatedAt.UTC(), e.ExpiresAt.UTC(),
			int64(e.Duration), e.RuleID, e.EvidenceID, e.RecidiveLevel, e.Status)
		return apperr.Wrap(op, err)
	default:
		return apperr.Wrap(op, err)
	}
}

// Get returns the most recent entry (by created_at, then id) for ip.
func (s *BanLifecycleStore) Get(ctx context.Context, ip string) (banlifecycle.Entry, bool, error) {
	const op = "storage.sqlite.BanLifecycleStore.Get"
	row := s.db.Conn().QueryRowContext(ctx, `
		SELECT ip, source, reason, confidence, created_at, expires_at, duration_ns,
		       rule_id, evidence_id, recidive_level, status
		FROM cf_ban_lifecycle
		WHERE ip = ?
		ORDER BY created_at DESC, id DESC
		LIMIT 1
	`, ip)
	e, err := scanBanLifecycleEntry(row)
	if errors.Is(err, sql.ErrNoRows) {
		return banlifecycle.Entry{}, false, nil
	}
	if err != nil {
		return banlifecycle.Entry{}, false, apperr.Wrap(op, err)
	}
	return e, true, nil
}

// Active returns every entry currently in StatusActive.
func (s *BanLifecycleStore) Active(ctx context.Context) ([]banlifecycle.Entry, error) {
	const op = "storage.sqlite.BanLifecycleStore.Active"
	rows, err := s.db.Conn().QueryContext(ctx, `
		SELECT ip, source, reason, confidence, created_at, expires_at, duration_ns,
		       rule_id, evidence_id, recidive_level, status
		FROM cf_ban_lifecycle
		WHERE status = ?
		ORDER BY created_at DESC, id DESC
	`, banlifecycle.StatusActive)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()
	return scanBanLifecycleEntries(op, rows)
}

// Expired returns every active entry whose expires_at is at or before now.
func (s *BanLifecycleStore) Expired(ctx context.Context, now time.Time) ([]banlifecycle.Entry, error) {
	const op = "storage.sqlite.BanLifecycleStore.Expired"
	rows, err := s.db.Conn().QueryContext(ctx, `
		SELECT ip, source, reason, confidence, created_at, expires_at, duration_ns,
		       rule_id, evidence_id, recidive_level, status
		FROM cf_ban_lifecycle
		WHERE status = ? AND expires_at <= ?
		ORDER BY created_at ASC, id ASC
	`, banlifecycle.StatusActive, now.UTC())
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()
	return scanBanLifecycleEntries(op, rows)
}

// MarkStatus updates the status (and, as a note, the status_note) of the
// current (most recent) entry for ip.
func (s *BanLifecycleStore) MarkStatus(ctx context.Context, ip string, status string, note string) error {
	const op = "storage.sqlite.BanLifecycleStore.MarkStatus"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	var id int64
	err := s.db.Conn().QueryRowContext(ctx, `
		SELECT id FROM cf_ban_lifecycle WHERE ip = ? ORDER BY created_at DESC, id DESC LIMIT 1
	`, ip).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return apperr.Wrap(op, err)
	}
	_, err = s.db.Conn().ExecContext(ctx, `
		UPDATE cf_ban_lifecycle SET status = ?, status_note = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, status, note, id)
	return apperr.Wrap(op, err)
}

// RecidiveLevel returns the count of prior non-active entries for ip.
func (s *BanLifecycleStore) RecidiveLevel(ctx context.Context, ip string) (int, error) {
	const op = "storage.sqlite.BanLifecycleStore.RecidiveLevel"
	var count int
	err := s.db.Conn().QueryRowContext(ctx, `
		SELECT COUNT(*) FROM cf_ban_lifecycle WHERE ip = ? AND status != ?
	`, ip, banlifecycle.StatusActive).Scan(&count)
	if err != nil {
		return 0, apperr.Wrap(op, err)
	}
	return count, nil
}

func scanBanLifecycleEntry(row *sql.Row) (banlifecycle.Entry, error) {
	var e banlifecycle.Entry
	var durationNS int64
	var createdAt, expiresAt time.Time
	if err := row.Scan(&e.IP, &e.Source, &e.Reason, &e.Confidence, &createdAt, &expiresAt,
		&durationNS, &e.RuleID, &e.EvidenceID, &e.RecidiveLevel, &e.Status); err != nil {
		return banlifecycle.Entry{}, err
	}
	e.CreatedAt = createdAt.UTC()
	e.ExpiresAt = expiresAt.UTC()
	e.Duration = time.Duration(durationNS)
	return e, nil
}

func scanBanLifecycleEntries(op string, rows *sql.Rows) ([]banlifecycle.Entry, error) {
	var out []banlifecycle.Entry
	for rows.Next() {
		var e banlifecycle.Entry
		var durationNS int64
		var createdAt, expiresAt time.Time
		if err := rows.Scan(&e.IP, &e.Source, &e.Reason, &e.Confidence, &createdAt, &expiresAt,
			&durationNS, &e.RuleID, &e.EvidenceID, &e.RecidiveLevel, &e.Status); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		e.CreatedAt = createdAt.UTC()
		e.ExpiresAt = expiresAt.UTC()
		e.Duration = time.Duration(durationNS)
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return out, nil
}
