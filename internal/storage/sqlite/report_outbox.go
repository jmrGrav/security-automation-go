package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"time"

	abmodels "github.com/jm/security-automation-go/internal/abuseipdb/models"
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type ReportReservationStore struct {
	db           *DB
	mu           sync.Mutex
	retention    time.Duration
	maxEntries   int
	cleanupEvery int
	writeCount   int
	lastCleanup  time.Time
	now          func() time.Time
}

func NewReportReservationStore(db *DB) *ReportReservationStore {
	return &ReportReservationStore{
		db:           db,
		retention:    180 * 24 * time.Hour,
		maxEntries:   25_000,
		cleanupEvery: 32,
		now:          time.Now,
	}
}

func (s *ReportReservationStore) Reserve(ctx context.Context, reservation reporting.ReportReservation) error {
	const op = "storage.sqlite.ReportReservationStore.Reserve"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	if reservation.ExpiresAt.IsZero() {
		if s.now != nil {
			reservation.ExpiresAt = s.now().UTC().Add(24 * time.Hour)
		} else {
			reservation.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
		}
	}
	if reservation.Status == "" {
		reservation.Status = reporting.ReportStatusPending
	}
	reportJSON, err := json.Marshal(reservation.Report)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	now := time.Now().UTC()
	if s.now != nil {
		now = s.now().UTC()
	}
	var existingEvidenceID string
	var existingKey string
	var existingExpiresAt time.Time
	var existingReportJSON string
	err = s.db.Conn().QueryRowContext(ctx, `
		SELECT evidence_id, idempotency_key, expires_at, report_json
		FROM abuseipdb_report_outbox
		WHERE ip = ? AND status = ?
	`, reservation.IP, reporting.ReportStatusPending).Scan(&existingEvidenceID, &existingKey, &existingExpiresAt, &existingReportJSON)
	if err != nil && err != sql.ErrNoRows {
		return apperr.Wrap(op, err)
	}
	if err == nil {
		if existingKey == reservation.IdempotencyKey {
			return nil
		}
		if now.Before(existingExpiresAt.UTC()) {
			var existingReport abmodels.ExecutableReport
			if err := json.Unmarshal([]byte(existingReportJSON), &existingReport); err != nil {
				return apperr.Wrap(op, err)
			}
			merged := reporting.MergeExecutableReports(existingReport, reservation.Report)
			mergedJSON, err := json.Marshal(merged)
			if err != nil {
				return apperr.Wrap(op, err)
			}
			nextAttempt := reservation.ExpiresAt.UTC()
			if nextAttempt.Before(existingExpiresAt.UTC()) {
				nextAttempt = existingExpiresAt.UTC()
			}
			if _, err := s.db.Conn().ExecContext(ctx, `
				UPDATE abuseipdb_report_outbox
				SET expires_at = ?, next_attempt_at = ?, report_json = ?, updated_at = CURRENT_TIMESTAMP
				WHERE evidence_id = ?
			`, nextAttempt, nextAttempt, string(mergedJSON), existingEvidenceID); err != nil {
				return apperr.Wrap(op, err)
			}
			return nil
		}
		if _, err := s.db.Conn().ExecContext(ctx, `
			UPDATE abuseipdb_report_outbox
			SET status = ?, updated_at = CURRENT_TIMESTAMP
			WHERE evidence_id = ?
		`, reporting.ReportStatusFailed, existingEvidenceID); err != nil {
			return apperr.Wrap(op, err)
		}
	}
	_, err = s.db.Conn().ExecContext(ctx, `
		INSERT INTO abuseipdb_report_outbox (
			evidence_id, ip, source, idempotency_key, status, expires_at, next_attempt_at, report_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, reservation.EvidenceID, reservation.IP, reservation.Source, reservation.IdempotencyKey, reservation.Status, reservation.ExpiresAt.UTC(), reservation.ExpiresAt.UTC(), string(reportJSON))
	if err == nil {
		s.noteWrite()
		if cleanupErr := s.cleanup(ctx); cleanupErr != nil {
			return cleanupErr
		}
	}
	return apperr.Wrap(op, err)
}

func (s *ReportReservationStore) FindPendingByIPAndIdempotencyKey(ctx context.Context, ip string, idempotencyKey string) (reporting.ReportReservation, bool, error) {
	const op = "storage.sqlite.ReportReservationStore.FindPendingByIPAndIdempotencyKey"
	if err := s.db.ensureWritable(op); err != nil {
		return reporting.ReportReservation{}, false, err
	}
	var reservation reporting.ReportReservation
	var reportJSON string
	err := s.db.Conn().QueryRowContext(ctx, `
		SELECT evidence_id, ip, source, idempotency_key, status, expires_at, report_json
		FROM abuseipdb_report_outbox
		WHERE ip = ? AND idempotency_key = ? AND status = ?
		ORDER BY updated_at DESC, evidence_id DESC
		LIMIT 1
	`, ip, idempotencyKey, reporting.ReportStatusPending).Scan(
		&reservation.EvidenceID,
		&reservation.IP,
		&reservation.Source,
		&reservation.IdempotencyKey,
		&reservation.Status,
		&reservation.ExpiresAt,
		&reportJSON,
	)
	if err == sql.ErrNoRows {
		return reporting.ReportReservation{}, false, nil
	}
	if err != nil {
		return reporting.ReportReservation{}, false, apperr.Wrap(op, err)
	}
	if err := json.Unmarshal([]byte(reportJSON), &reservation.Report); err != nil {
		return reporting.ReportReservation{}, false, apperr.Wrap(op, err)
	}
	return reservation, true, nil
}

func (s *ReportReservationStore) MarkStatus(ctx context.Context, evidenceID string, status string) error {
	const op = "storage.sqlite.ReportReservationStore.MarkStatus"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	res, err := s.db.Conn().ExecContext(ctx, `
		UPDATE abuseipdb_report_outbox
		SET status = ?, updated_at = CURRENT_TIMESTAMP
		WHERE evidence_id = ?
	`, status, evidenceID)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if rows, err := res.RowsAffected(); err == nil && rows == 0 {
		return apperr.Newf(op, "report reservation not found: %s", evidenceID)
	}
	s.noteWrite()
	if cleanupErr := s.cleanup(ctx); cleanupErr != nil {
		return cleanupErr
	}
	return apperr.Wrap(op, err)
}

func (s *ReportReservationStore) ClaimRetryable(ctx context.Context, now time.Time, limit int, claimUntil time.Time) ([]reporting.ReportOutboxItem, error) {
	const op = "storage.sqlite.ReportReservationStore.ClaimRetryable"
	if limit <= 0 {
		limit = 50
	}
	if err := s.cleanup(ctx); err != nil {
		return nil, err
	}
	tx, err := s.db.Conn().BeginTx(ctx, &sql.TxOptions{})
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT evidence_id, ip, source, idempotency_key, status, expires_at, report_json,
		       attempt_count, last_error, next_attempt_at
		FROM abuseipdb_report_outbox
		WHERE status IN (?, ?)
		  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
		ORDER BY updated_at ASC, evidence_id ASC
		LIMIT ?
	`, reporting.ReportStatusPending, reporting.ReportStatusFailed, now.UTC(), limit)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()

	var out []reporting.ReportOutboxItem
	for rows.Next() {
		var item reporting.ReportOutboxItem
		var reportJSON string
		var nextAttempt sql.NullTime
		if err := rows.Scan(
			&item.Reservation.EvidenceID,
			&item.Reservation.IP,
			&item.Reservation.Source,
			&item.Reservation.IdempotencyKey,
			&item.Reservation.Status,
			&item.Reservation.ExpiresAt,
			&reportJSON,
			&item.AttemptCount,
			&item.LastError,
			&nextAttempt,
		); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		if err := json.Unmarshal([]byte(reportJSON), &item.Reservation.Report); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		if nextAttempt.Valid {
			item.NextAttemptAt = nextAttempt.Time.UTC()
		}
		res, err := tx.ExecContext(ctx, `
			UPDATE abuseipdb_report_outbox
			SET next_attempt_at = ?, updated_at = CURRENT_TIMESTAMP
			WHERE evidence_id = ? AND status = ?
			  AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
		`, claimUntil.UTC(), item.Reservation.EvidenceID, item.Reservation.Status, now.UTC())
		if err != nil {
			return nil, apperr.Wrap(op, err)
		}
		rowsAffected, err := res.RowsAffected()
		if err != nil {
			return nil, apperr.Wrap(op, err)
		}
		if rowsAffected == 0 {
			continue
		}
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	if err := tx.Commit(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return out, nil
}

func (s *ReportReservationStore) ListRetryable(ctx context.Context, now time.Time, limit int) ([]reporting.ReportOutboxItem, error) {
	return s.ClaimRetryable(ctx, now, limit, now)
}

func (s *ReportReservationStore) RecordAttempt(ctx context.Context, evidenceID string, status string, lastError string, nextAttemptAt time.Time) error {
	const op = "storage.sqlite.ReportReservationStore.RecordAttempt"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	var next any
	if !nextAttemptAt.IsZero() {
		next = nextAttemptAt.UTC()
	}
	res, err := s.db.Conn().ExecContext(ctx, `
		UPDATE abuseipdb_report_outbox
		SET status = ?,
		    attempt_count = attempt_count + 1,
		    last_error = ?,
		    next_attempt_at = ?,
		    updated_at = CURRENT_TIMESTAMP
		WHERE evidence_id = ?
	`, status, lastError, next, evidenceID)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if rows, err := res.RowsAffected(); err == nil && rows == 0 {
		return apperr.Newf(op, "report reservation not found: %s", evidenceID)
	}
	s.noteWrite()
	if cleanupErr := s.cleanup(ctx); cleanupErr != nil {
		return cleanupErr
	}
	return nil
}

func (s *ReportReservationStore) noteWrite() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.writeCount++
	s.mu.Unlock()
}

func (s *ReportReservationStore) cleanup(ctx context.Context) error {
	if s == nil || s.db == nil || s.db.ReadOnlyDegradedMode() {
		return nil
	}
	now := s.now
	if now == nil {
		now = time.Now
	}
	current := now().UTC()
	s.mu.Lock()
	if s.cleanupEvery > 0 && s.writeCount%s.cleanupEvery != 0 {
		if !s.lastCleanup.IsZero() && current.Sub(s.lastCleanup) < 5*time.Minute {
			s.mu.Unlock()
			return nil
		}
	}
	s.lastCleanup = current
	s.mu.Unlock()

	if err := s.purgeExpired(ctx, current.Add(-s.retention)); err != nil {
		return err
	}
	if err := s.trimToMaxEntries(ctx, s.maxEntries); err != nil {
		return err
	}
	return nil
}

func (s *ReportReservationStore) purgeExpired(ctx context.Context, cutoff time.Time) error {
	const op = "storage.sqlite.ReportReservationStore.PurgeExpired"
	if s == nil || cutoff.IsZero() {
		return nil
	}
	res, err := s.db.Conn().ExecContext(ctx, `
		DELETE FROM abuseipdb_report_outbox
		WHERE (status IN (?, ?, ?) AND updated_at < ?)
		   OR (status = ? AND expires_at < ?)
	`, reporting.ReportStatusReported, reporting.ReportStatusFailed, reporting.ReportStatusReportedDedupFailed, cutoff.UTC(), reporting.ReportStatusPending, cutoff.UTC())
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if affected, rowsErr := res.RowsAffected(); rowsErr == nil && affected > 0 {
		metrics.ReportOutboxPrunedTotal.Add(float64(affected))
	}
	return nil
}

func (s *ReportReservationStore) trimToMaxEntries(ctx context.Context, maxEntries int) error {
	const op = "storage.sqlite.ReportReservationStore.TrimToMaxEntries"
	if s == nil || maxEntries <= 0 {
		return nil
	}
	var total int
	if err := s.db.Conn().QueryRowContext(ctx, `SELECT COUNT(1) FROM abuseipdb_report_outbox`).Scan(&total); err != nil {
		return apperr.Wrap(op, err)
	}
	if total <= maxEntries {
		return nil
	}
	overflow := total - maxEntries
	res, err := s.db.Conn().ExecContext(ctx, `
		DELETE FROM abuseipdb_report_outbox
		WHERE evidence_id IN (
			SELECT evidence_id
			FROM abuseipdb_report_outbox
			ORDER BY updated_at ASC, evidence_id ASC
			LIMIT ?
		)
	`, overflow)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	if affected, rowsErr := res.RowsAffected(); rowsErr == nil && affected > 0 {
		metrics.ReportOutboxPrunedTotal.Add(float64(affected))
	}
	return nil
}
