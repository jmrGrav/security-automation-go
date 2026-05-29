package sqlite

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/execution"
)

type ApprovalEvidenceStore struct {
	db *DB
}

func NewApprovalEvidenceStore(db *DB) *ApprovalEvidenceStore {
	return &ApprovalEvidenceStore{db: db}
}

func (s *ApprovalEvidenceStore) Append(ctx context.Context, evidence execution.ApprovalEvidence) error {
	const op = "storage.sqlite.ApprovalEvidenceStore.Append"
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
		INSERT INTO approval_execution_evidence (
			evidence_id, timestamp, approval_id, batch_id, operation_id, status, data
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`, evidence.EvidenceID, evidence.Timestamp.UTC(), evidence.ApprovalID, evidence.BatchID, evidence.OperationID, evidence.Status, string(data))
	return apperr.Wrap(op, err)
}
