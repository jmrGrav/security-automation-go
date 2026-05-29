package execution

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/snapshot"
)

type mockMutator struct {
	executed bool
}

func (m *mockMutator) Execute(op MutationOperation) (string, error) {
	m.executed = true
	return "res-123", nil
}

func (m *mockMutator) DryRun(op MutationOperation) string {
	return "mock"
}

type memoryApprovalEvidenceStore struct {
	items []ApprovalEvidence
}

func (m *memoryApprovalEvidenceStore) Append(_ context.Context, evidence ApprovalEvidence) error {
	m.items = append(m.items, evidence)
	return nil
}

func TestGovernedExecutor_ExecuteBatch(t *testing.T) {
	j := journal.NewJSONLJournal(t.TempDir() + "/audit.jsonl")
	cb := breaker.New(5, time.Minute, time.Minute)
	reg := resources.NewRegistry()
	exec := NewGovernedExecutor(j, cb, reg)

	mut := &mockMutator{}
	rt := string(snapshot.ResourceIPAccessRules)
	exec.RegisterMutator(rt, mut)

	batch := MutationBatch{
		ID:     "b1",
		PlanID: "p1",
		Operations: []MutationOperation{
			{OperationID: "o1", ResourceType: rt, StableIdentityKey: "k1", Type: "create"},
		},
	}

	err := exec.ExecuteBatch(context.Background(), batch)
	if err != nil {
		t.Fatalf("ExecuteBatch failed: %v", err)
	}

	if !mut.executed {
		t.Error("mutator was not executed")
	}
}

func TestGovernedExecutor_BreakerOpen(t *testing.T) {
	j := journal.NewJSONLJournal(t.TempDir() + "/audit.jsonl")
	cb := breaker.New(1, time.Minute, time.Minute)
	cb.RecordFailure() // Open the breaker

	reg := resources.NewRegistry()
	exec := NewGovernedExecutor(j, cb, reg)

	batch := MutationBatch{
		ID: "b1",
		Operations: []MutationOperation{
			{OperationID: "o1", ResourceType: string(snapshot.ResourceIPAccessRules)},
		},
	}

	err := exec.ExecuteBatch(context.Background(), batch)
	if err == nil || !strings.Contains(err.Error(), "circuit breaker is open") {
		t.Errorf("expected breaker error, got %v", err)
	}
}

func TestGovernedExecutor_ApprovalRequired(t *testing.T) {
	j := journal.NewJSONLJournal(t.TempDir() + "/audit.jsonl")
	cb := breaker.New(5, time.Minute, time.Minute)
	reg := resources.NewRegistry()
	exec := NewGovernedExecutor(j, cb, reg)
	approvalStore := &memoryApprovalEvidenceStore{}
	exec.SetApprovalEvidenceStore(approvalStore)

	mut := &mockMutator{}
	rt := string(snapshot.ResourceIPAccessRules)
	exec.RegisterMutator(rt, mut)

	batch := MutationBatch{
		ID:               "b2",
		ApprovalRequired: true,
		ApprovalStatus:   ApprovalPending,
		Operations: []MutationOperation{
			{OperationID: "o1", ResourceType: rt, StableIdentityKey: "k1", Type: "create"},
		},
	}

	err := exec.ExecuteBatch(context.Background(), batch)
	if err == nil || !strings.Contains(err.Error(), "requires approval") {
		t.Fatalf("expected approval error, got %v", err)
	}
	if mut.executed {
		t.Fatal("mutator should not have been executed")
	}
	if len(approvalStore.items) != 2 {
		t.Fatalf("expected two approval evidence entries, got %d", len(approvalStore.items))
	}
	if approvalStore.items[0].Event != "approval_required" {
		t.Fatalf("expected approval_required evidence first, got %+v", approvalStore.items[0])
	}
	if approvalStore.items[1].Event != "awaiting_approval" {
		t.Fatalf("expected awaiting_approval evidence second, got %+v", approvalStore.items[1])
	}
	if approvalStore.items[1].ParentEvidenceID != approvalStore.items[0].EvidenceID {
		t.Fatalf("expected awaiting_approval parent evidence %q, got %q", approvalStore.items[0].EvidenceID, approvalStore.items[1].ParentEvidenceID)
	}
	if approvalStore.items[1].Status != ApprovalPending {
		t.Fatalf("expected pending approval evidence, got %+v", approvalStore.items[0])
	}
}

func TestGovernedExecutor_ApprovalDenied(t *testing.T) {
	j := journal.NewJSONLJournal(t.TempDir() + "/audit.jsonl")
	cb := breaker.New(5, time.Minute, time.Minute)
	reg := resources.NewRegistry()
	exec := NewGovernedExecutor(j, cb, reg)
	approvalStore := &memoryApprovalEvidenceStore{}
	exec.SetApprovalEvidenceStore(approvalStore)

	mut := &mockMutator{}
	rt := string(snapshot.ResourceIPAccessRules)
	exec.RegisterMutator(rt, mut)

	batch := MutationBatch{
		ID:               "b-denied",
		ApprovalRequired: true,
		ApprovalStatus:   ApprovalRejected,
		Operations: []MutationOperation{
			{OperationID: "o1", ResourceType: rt, StableIdentityKey: "k1", Type: "create"},
		},
	}

	err := exec.ExecuteBatch(context.Background(), batch)
	if err == nil || !strings.Contains(err.Error(), "approval denied") {
		t.Fatalf("expected approval denied error, got %v", err)
	}
	if mut.executed {
		t.Fatal("mutator should not execute when approval is denied")
	}
	if len(approvalStore.items) != 2 {
		t.Fatalf("expected two approval evidence entries, got %d", len(approvalStore.items))
	}
	if approvalStore.items[1].Event != "approval_denied" {
		t.Fatalf("expected approval_denied evidence, got %+v", approvalStore.items[1])
	}
}

func TestGovernedExecutor_ApprovalExpired(t *testing.T) {
	j := journal.NewJSONLJournal(t.TempDir() + "/audit.jsonl")
	cb := breaker.New(5, time.Minute, time.Minute)
	reg := resources.NewRegistry()
	exec := NewGovernedExecutor(j, cb, reg)
	approvalStore := &memoryApprovalEvidenceStore{}
	exec.SetApprovalEvidenceStore(approvalStore)

	mut := &mockMutator{}
	rt := string(snapshot.ResourceIPAccessRules)
	exec.RegisterMutator(rt, mut)

	batch := MutationBatch{
		ID:                "b-expired",
		ApprovalRequired:  true,
		ApprovalStatus:    ApprovalApproved,
		ApprovalExpiresAt: time.Now().UTC().Add(-time.Minute),
		Operations: []MutationOperation{
			{OperationID: "o1", ResourceType: rt, StableIdentityKey: "k1", Type: "create"},
		},
	}

	err := exec.ExecuteBatch(context.Background(), batch)
	if err == nil || !strings.Contains(err.Error(), "approval expired") {
		t.Fatalf("expected approval expired error, got %v", err)
	}
	if mut.executed {
		t.Fatal("mutator should not execute when approval is expired")
	}
	if len(approvalStore.items) != 2 {
		t.Fatalf("expected two approval evidence entries, got %d", len(approvalStore.items))
	}
	if approvalStore.items[1].Event != "approval_expired" {
		t.Fatalf("expected approval_expired evidence, got %+v", approvalStore.items[1])
	}
}

func TestGovernedExecutor_ApprovalGrantedAllowsExecution(t *testing.T) {
	j := journal.NewJSONLJournal(t.TempDir() + "/audit.jsonl")
	cb := breaker.New(5, time.Minute, time.Minute)
	reg := resources.NewRegistry()
	exec := NewGovernedExecutor(j, cb, reg)
	approvalStore := &memoryApprovalEvidenceStore{}
	exec.SetApprovalEvidenceStore(approvalStore)

	mut := &mockMutator{}
	rt := string(snapshot.ResourceIPAccessRules)
	exec.RegisterMutator(rt, mut)

	batch := MutationBatch{
		ID:                "b-granted",
		ApprovalRequired:  true,
		ApprovalStatus:    ApprovalApproved,
		ApprovalExpiresAt: time.Now().UTC().Add(time.Minute),
		Operations: []MutationOperation{
			{OperationID: "o1", ResourceType: rt, StableIdentityKey: "k1", Type: "create"},
		},
	}

	if err := exec.ExecuteBatch(context.Background(), batch); err != nil {
		t.Fatalf("expected execution with granted approval, got %v", err)
	}
	if !mut.executed {
		t.Fatal("mutator should execute with granted approval")
	}
	foundGranted := false
	for _, item := range approvalStore.items {
		if item.Event == "approval_granted" {
			foundGranted = true
			break
		}
	}
	if !foundGranted {
		t.Fatalf("expected approval_granted evidence in %+v", approvalStore.items)
	}
}
