package execution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"
)

type ApprovalEvidence struct {
	EvidenceID       string         `json:"evidence_id"`
	Timestamp        time.Time      `json:"timestamp"`
	Event            string         `json:"event"`
	ScopeID          string         `json:"scope_id,omitempty"`
	BatchID          string         `json:"batch_id,omitempty"`
	OperationID      string         `json:"operation_id,omitempty"`
	PlanID           string         `json:"plan_id,omitempty"`
	ApprovalID       string         `json:"approval_id,omitempty"`
	Status           ApprovalStatus `json:"status"`
	Reason           string         `json:"reason,omitempty"`
	ApprovedBy       string         `json:"approved_by,omitempty"`
	RequestedAt      time.Time      `json:"requested_at,omitempty"`
	DecidedAt        time.Time      `json:"decided_at,omitempty"`
	ExpiresAt        time.Time      `json:"expires_at,omitempty"`
	ApprovalReason   string         `json:"approval_reason,omitempty"`
	MutationType     string         `json:"mutation_type,omitempty"`
	RiskLevel        string         `json:"risk_level,omitempty"`
	ParentEvidenceID string         `json:"parent_evidence_id,omitempty"`
	LineageID        string         `json:"lineage_id"`
	DecisionHash     string         `json:"decision_hash"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

type ApprovalEvidenceStore interface {
	Append(ctx context.Context, evidence ApprovalEvidence) error
}

func approvalLineageID(batch MutationBatch, op *MutationOperation) string {
	target := batch.ID + "|" + batch.PlanID + "|" + batch.ApprovalID
	if op != nil {
		target += "|" + op.OperationID + "|" + op.ApprovalID
	}
	sum := sha256.Sum256([]byte(target))
	return hex.EncodeToString(sum[:16])
}

func approvalEvidenceID(batch MutationBatch, op *MutationOperation, at time.Time) string {
	target := fmt.Sprintf("%s|%s|%d", approvalLineageID(batch, op), decisionTargetID(op), at.UTC().UnixNano())
	sum := sha256.Sum256([]byte(target))
	return "approval-" + hex.EncodeToString(sum[:12])
}

func approvalDecisionHash(batch MutationBatch, op *MutationOperation, event string, reason string) string {
	payload, _ := json.Marshal(struct {
		Event             string         `json:"event"`
		BatchID           string         `json:"batch_id,omitempty"`
		OperationID       string         `json:"operation_id,omitempty"`
		ApprovalID        string         `json:"approval_id,omitempty"`
		ApprovalStatus    ApprovalStatus `json:"approval_status"`
		ApprovalRequired  bool           `json:"approval_required"`
		ApprovalExpiresAt time.Time      `json:"approval_expires_at,omitempty"`
		ApprovedBy        string         `json:"approved_by,omitempty"`
		ApprovalReason    string         `json:"approval_reason,omitempty"`
		Reason            string         `json:"reason,omitempty"`
	}{
		Event:             event,
		BatchID:           batch.ID,
		OperationID:       decisionTargetID(op),
		ApprovalID:        approvalID(batch, op),
		ApprovalStatus:    approvalStatus(batch, op),
		ApprovalRequired:  approvalRequired(batch, op),
		ApprovalExpiresAt: approvalExpiresAt(batch, op),
		ApprovedBy:        approvedBy(batch, op),
		ApprovalReason:    approvalReason(batch, op),
		Reason:            reason,
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func decisionTargetID(op *MutationOperation) string {
	if op == nil {
		return ""
	}
	return op.OperationID
}

func approvalID(batch MutationBatch, op *MutationOperation) string {
	if op != nil && op.ApprovalID != "" {
		return op.ApprovalID
	}
	return batch.ApprovalID
}

func approvalStatus(batch MutationBatch, op *MutationOperation) ApprovalStatus {
	if op != nil && op.ApprovalRequired {
		return op.ApprovalStatus
	}
	return batch.ApprovalStatus
}

func approvalRequired(batch MutationBatch, op *MutationOperation) bool {
	if op != nil && op.ApprovalRequired {
		return true
	}
	return batch.ApprovalRequired
}

func approvalExpiresAt(batch MutationBatch, op *MutationOperation) time.Time {
	if op != nil && !op.ApprovalExpiresAt.IsZero() {
		return op.ApprovalExpiresAt
	}
	return batch.ApprovalExpiresAt
}

func approvedBy(batch MutationBatch, op *MutationOperation) string {
	if op != nil && op.ApprovedBy != "" {
		return op.ApprovedBy
	}
	return batch.ApprovedBy
}

func approvalReason(batch MutationBatch, op *MutationOperation) string {
	if op != nil && op.ApprovalReason != "" {
		return op.ApprovalReason
	}
	return batch.ApprovalReason
}

func approvalScope(batch MutationBatch, op *MutationOperation) string {
	if op != nil && op.ScopeID != "" {
		return op.ScopeID
	}
	return batch.ScopeID
}

func mutationType(op *MutationOperation) string {
	if op == nil {
		return ""
	}
	return string(op.Type)
}

func riskLevel(batch MutationBatch, op *MutationOperation) string {
	if op != nil {
		switch op.Type {
		case "delete":
			return "high"
		case "update":
			return "medium"
		default:
			return "low"
		}
	}
	if batch.DestructiveCount > 0 {
		return "high"
	}
	return "low"
}
