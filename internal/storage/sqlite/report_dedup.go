package sqlite

import (
	"context"
	"database/sql"
	"net/netip"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
)

type AbuseReportDedupStore struct {
	db *DB
}

func NewAbuseReportDedupStore(db *DB) *AbuseReportDedupStore {
	return &AbuseReportDedupStore{db: db}
}

func (s *AbuseReportDedupStore) LastReportedAt(ctx context.Context, ip netip.Addr) (time.Time, bool, error) {
	const op = "storage.sqlite.AbuseReportDedupStore.LastReportedAt"

	var reportedAt time.Time
	err := s.db.Conn().QueryRowContext(
		ctx,
		"SELECT last_reported_at FROM abuseipdb_report_dedup WHERE ip = ?",
		ip.String(),
	).Scan(&reportedAt)
	if err == sql.ErrNoRows {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, apperr.Wrap(op, err)
	}
	return reportedAt.UTC(), true, nil
}

func (s *AbuseReportDedupStore) MarkReported(ctx context.Context, ip netip.Addr, reportedAt time.Time, evidenceID string) error {
	const op = "storage.sqlite.AbuseReportDedupStore.MarkReported"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	if reportedAt.IsZero() {
		reportedAt = time.Now().UTC()
	}
	if evidenceID == "" {
		evidenceID = "unknown"
	}
	_, err := s.db.Conn().ExecContext(ctx, `
		INSERT INTO abuseipdb_report_dedup (
			ip, last_reported_at, last_evidence_id, report_count, updated_at
		) VALUES (?, ?, ?, 1, ?)
		ON CONFLICT(ip) DO UPDATE SET
			last_reported_at = excluded.last_reported_at,
			last_evidence_id = excluded.last_evidence_id,
			report_count = abuseipdb_report_dedup.report_count + 1,
			updated_at = excluded.updated_at
	`, ip.String(), reportedAt.UTC(), evidenceID, reportedAt.UTC())
	return apperr.Wrap(op, err)
}
