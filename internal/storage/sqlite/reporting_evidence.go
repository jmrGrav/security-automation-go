package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type ReportingEvidenceStore struct {
	db *DB
}

func NewReportingEvidenceStore(db *DB) *ReportingEvidenceStore {
	return &ReportingEvidenceStore{db: db}
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
