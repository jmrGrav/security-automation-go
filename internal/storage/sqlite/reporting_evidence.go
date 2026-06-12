package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type ReportingEvidenceStore struct {
	db           *DB
	mu           sync.Mutex
	retention    time.Duration
	maxEntries   int
	cleanupEvery int
	writeCount   int
	lastCleanup  time.Time
	now          func() time.Time
}

func NewReportingEvidenceStore(db *DB) *ReportingEvidenceStore {
	return &ReportingEvidenceStore{
		db:           db,
		retention:    180 * 24 * time.Hour,
		maxEntries:   50_000,
		cleanupEvery: 32,
		now:          time.Now,
	}
}

func (s *ReportingEvidenceStore) Append(ctx context.Context, evidence reporting.DecisionEvidence) error {
	const op = "storage.sqlite.ReportingEvidenceStore.Append"
	if err := s.db.ensureWritable(op); err != nil {
		return err
	}
	if evidence.Timestamp.IsZero() {
		evidence.Timestamp = time.Now().UTC()
	}
	data, err := json.Marshal(evidence)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	_, err = s.db.Conn().ExecContext(ctx, `
		INSERT INTO abuseipdb_reporting_evidence (
			evidence_id, timestamp, source, ip, suppression_reason, decision, abuse_type, data
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, evidence.EvidenceID, evidence.Timestamp.UTC(), evidence.Source, evidence.IP, evidence.SuppressionReason, evidence.Decision, evidence.AbuseType, string(data))
	if err == nil {
		s.noteWrite()
		if cleanupErr := s.cleanup(ctx); cleanupErr != nil {
			return cleanupErr
		}
	}
	return apperr.Wrap(op, err)
}

func (s *ReportingEvidenceStore) List(ctx context.Context, limit int) ([]reporting.DecisionEvidence, error) {
	return s.Search(ctx, reporting.EvidenceSearchOptions{Limit: limit})
}

func (s *ReportingEvidenceStore) Get(ctx context.Context, evidenceID string) (reporting.DecisionEvidence, bool, error) {
	const op = "storage.sqlite.ReportingEvidenceStore.Get"
	row := s.db.Conn().QueryRowContext(ctx, `
		SELECT data
		FROM abuseipdb_reporting_evidence
		WHERE evidence_id = ?
	`, evidenceID)
	var raw string
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return reporting.DecisionEvidence{}, false, nil
		}
		return reporting.DecisionEvidence{}, false, apperr.Wrap(op, err)
	}
	var evidence reporting.DecisionEvidence
	if err := json.Unmarshal([]byte(raw), &evidence); err != nil {
		return reporting.DecisionEvidence{}, false, apperr.Wrap(op, err)
	}
	return evidence, true, nil
}

func (s *ReportingEvidenceStore) Search(ctx context.Context, opts reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	const op = "storage.sqlite.ReportingEvidenceStore.List"
	if err := s.cleanup(ctx); err != nil {
		return nil, err
	}
	query := `
		SELECT data, source, ip, suppression_reason, timestamp
		FROM abuseipdb_reporting_evidence
		WHERE 1=1
	`
	args := []any{}
	if strings.TrimSpace(opts.IP) != "" {
		query += " AND ip = ?"
		args = append(args, strings.TrimSpace(opts.IP))
	}
	if strings.TrimSpace(opts.Source) != "" {
		query += " AND source = ?"
		args = append(args, strings.TrimSpace(opts.Source))
	}
	if strings.TrimSpace(opts.SuppressionReason) != "" {
		query += " AND suppression_reason = ?"
		args = append(args, strings.TrimSpace(opts.SuppressionReason))
	}
	if strings.TrimSpace(opts.Decision) != "" {
		query += " AND decision = ?"
		args = append(args, strings.TrimSpace(opts.Decision))
	}
	if opts.AbuseIPDBReported {
		query += " AND json_extract(data, '$.abuseipdb_reported') = 1"
	}
	if opts.Suppressed {
		query += " AND json_extract(data, '$.suppressed') = 1"
	}
	if !opts.From.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, opts.From.UTC())
	}
	if !opts.To.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, opts.To.UTC())
	}
	query += " ORDER BY timestamp DESC, evidence_id DESC"
	if opts.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, opts.Limit)
	}
	if opts.Offset > 0 {
		if opts.Limit <= 0 {
			query += " LIMIT ?"
			args = append(args, 100)
		}
		query += " OFFSET ?"
		args = append(args, opts.Offset)
	}
	rows, err := s.db.Conn().QueryContext(ctx, query, args...)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer rows.Close()

	var out []reporting.DecisionEvidence
	for rows.Next() {
		var raw string
		var source string
		var ip string
		var suppressionReason any
		var timestamp time.Time
		if err := rows.Scan(&raw, &source, &ip, &suppressionReason, &timestamp); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		var evidence reporting.DecisionEvidence
		if err := json.Unmarshal([]byte(raw), &evidence); err != nil {
			return nil, apperr.Wrap(op, err)
		}
		_ = source
		_ = ip
		_ = suppressionReason
		_ = timestamp
		out = append(out, evidence)
	}
	if err := rows.Err(); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	return out, nil
}

func (s *ReportingEvidenceStore) Count(ctx context.Context, opts reporting.EvidenceSearchOptions) (int, error) {
	const op = "storage.sqlite.ReportingEvidenceStore.Count"
	query := `SELECT COUNT(*) FROM abuseipdb_reporting_evidence WHERE 1=1`
	args := []any{}
	if strings.TrimSpace(opts.IP) != "" {
		query += " AND ip = ?"
		args = append(args, strings.TrimSpace(opts.IP))
	}
	if strings.TrimSpace(opts.Source) != "" {
		query += " AND source = ?"
		args = append(args, strings.TrimSpace(opts.Source))
	}
	if strings.TrimSpace(opts.SuppressionReason) != "" {
		query += " AND suppression_reason = ?"
		args = append(args, strings.TrimSpace(opts.SuppressionReason))
	}
	if strings.TrimSpace(opts.Decision) != "" {
		query += " AND decision = ?"
		args = append(args, strings.TrimSpace(opts.Decision))
	}
	if opts.AbuseIPDBReported {
		query += " AND json_extract(data, '$.abuseipdb_reported') = 1"
	}
	if opts.Suppressed {
		query += " AND json_extract(data, '$.suppressed') = 1"
	}
	if !opts.From.IsZero() {
		query += " AND timestamp >= ?"
		args = append(args, opts.From.UTC())
	}
	if !opts.To.IsZero() {
		query += " AND timestamp <= ?"
		args = append(args, opts.To.UTC())
	}
	var count int
	err := s.db.Conn().QueryRowContext(ctx, query, args...).Scan(&count)
	return count, apperr.Wrap(op, err)
}

func (s *ReportingEvidenceStore) noteWrite() {
	if s == nil {
		return
	}
	s.mu.Lock()
	s.writeCount++
	s.mu.Unlock()
}

func (s *ReportingEvidenceStore) cleanup(ctx context.Context) error {
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

	if err := s.purgeBefore(ctx, current.Add(-s.retention)); err != nil {
		return err
	}
	if err := s.trimToMaxEntries(ctx, s.maxEntries); err != nil {
		return err
	}
	return nil
}

func (s *ReportingEvidenceStore) purgeBefore(ctx context.Context, cutoff time.Time) error {
	const op = "storage.sqlite.ReportingEvidenceStore.PurgeBefore"
	if s == nil || cutoff.IsZero() {
		return nil
	}
	res, err := s.db.Conn().ExecContext(ctx, `
		DELETE FROM abuseipdb_reporting_evidence
		WHERE timestamp < ?
	`, cutoff.UTC())
	if err == nil {
		if affected, rowsErr := res.RowsAffected(); rowsErr == nil && affected > 0 {
			metrics.ReportingEvidencePrunedTotal.Add(float64(affected))
		}
	}
	return apperr.Wrap(op, err)
}

func (s *ReportingEvidenceStore) trimToMaxEntries(ctx context.Context, maxEntries int) error {
	const op = "storage.sqlite.ReportingEvidenceStore.TrimToMaxEntries"
	if s == nil || maxEntries <= 0 {
		return nil
	}
	var total int
	if err := s.db.Conn().QueryRowContext(ctx, `SELECT COUNT(1) FROM abuseipdb_reporting_evidence`).Scan(&total); err != nil {
		return apperr.Wrap(op, err)
	}
	if total <= maxEntries {
		return nil
	}
	overflow := total - maxEntries
	res, err := s.db.Conn().ExecContext(ctx, `
		DELETE FROM abuseipdb_reporting_evidence
		WHERE evidence_id IN (
			SELECT evidence_id
			FROM abuseipdb_reporting_evidence
			ORDER BY timestamp ASC, evidence_id ASC
			LIMIT ?
		)
	`, overflow)
	if err == nil {
		if affected, rowsErr := res.RowsAffected(); rowsErr == nil && affected > 0 {
			metrics.ReportingEvidencePrunedTotal.Add(float64(affected))
		}
	}
	return apperr.Wrap(op, err)
}
