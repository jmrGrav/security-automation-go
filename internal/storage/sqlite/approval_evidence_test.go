package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/execution"
)

func TestApprovalEvidenceStoreAppend(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewApprovalEvidenceStore(db)
	ev := execution.ApprovalEvidence{
		EvidenceID:   "approval-1",
		Timestamp:    time.Date(2026, 5, 28, 0, 0, 0, 0, time.UTC),
		BatchID:      "batch-1",
		OperationID:  "op-1",
		ApprovalID:   "approval-gate-1",
		Status:       execution.ApprovalPending,
		Reason:       "approval required before execution",
		LineageID:    "lineage-1",
		DecisionHash: "hash-1",
	}
	if err := store.Append(context.Background(), ev); err != nil {
		t.Fatalf("append approval evidence: %v", err)
	}

	var count int
	if err := db.Conn().QueryRowContext(context.Background(), "SELECT COUNT(*) FROM approval_execution_evidence WHERE evidence_id = ?", ev.EvidenceID).Scan(&count); err != nil {
		t.Fatalf("count approval evidence rows: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected one approval evidence row, got %d", count)
	}
}
