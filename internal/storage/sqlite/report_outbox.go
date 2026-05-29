package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type ReportReservationStore struct {
	db *DB
}

func NewReportReservationStore(db *DB) *ReportReservationStore {
	return &ReportReservationStore{db: db}
}

func (s *ReportReservationStore) Reserve(ctx context.Context, reservation reporting.ReportReservation) error {
	const op = "storage.sqlite.ReportReservationStore.Reserve"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	if reservation.ExpiresAt.IsZero() {
		reservation.ExpiresAt = time.Now().UTC().Add(24 * time.Hour)
	}
	if reservation.Status == "" {
		reservation.Status = reporting.ReportStatusPending
	}
	reportJSON, err := json.Marshal(reservation.Report)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	now := time.Now().UTC()
	var existingEvidenceID string
	var existingKey string
	var existingExpiresAt time.Time
	err = s.db.Conn().QueryRowContext(ctx, `
		SELECT evidence_id, idempotency_key, expires_at
		FROM abuseipdb_report_outbox
		WHERE ip = ? AND status = ?
	`, reservation.IP, reporting.ReportStatusPending).Scan(&existingEvidenceID, &existingKey, &existingExpiresAt)
	if err != nil && err != sql.ErrNoRows {
		return apperr.Wrap(op, err)
	}
	if err == nil {
		if existingKey == reservation.IdempotencyKey {
			return nil
		}
		if now.Before(existingExpiresAt.UTC()) {
			return apperr.Newf(op, "pending AbuseIPDB report reservation exists for ip %s", reservation.IP)
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
			evidence_id, ip, source, idempotency_key, status, expires_at, report_json, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`, reservation.EvidenceID, reservation.IP, reservation.Source, reservation.IdempotencyKey, reservation.Status, reservation.ExpiresAt.UTC(), string(reportJSON))
	return apperr.Wrap(op, err)
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
	return apperr.Wrap(op, err)
}

func (s *ReportReservationStore) ListRetryable(ctx context.Context, now time.Time, limit int) ([]reporting.ReportOutboxItem, error) {
	const op = "storage.sqlite.ReportReservationStore.ListRetryable"
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.db.Conn().QueryContext(ctx, `
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
		out = append(out, item)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return out, nil
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
	return nil
}
