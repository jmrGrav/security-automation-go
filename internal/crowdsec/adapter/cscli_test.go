package adapter_test

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/adapter"
	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// ── DryRunExecutor tests ──────────────────────────────────────────────────────

func TestDryRunExecutor_AlwaysSucceeds(t *testing.T) {
	exec := adapter.NewDryRunExecutor()
	batch := models.Batch{
		ID: "dry-1",
		Actions: []models.ExecutableOperation{
			{
				ExecutionID:       "e1",
				Type:              models.ActionAddDecision,
				StableIdentityKey: "ip:1.2.3.4",
				Scope:             "ip",
				Value:             "1.2.3.4",
				Duration:          "4h",
				Reason:            "test",
				OriginatingOpID:   "op1",
			},
		},
	}

	result, err := exec.Execute(context.Background(), batch)
	if err != nil {
		t.Fatalf("DryRunExecutor.Execute error: %v", err)
	}
	if !result.Success {
		t.Error("dry-run result must be Success=true")
	}
	if len(result.Results) != 1 {
		t.Errorf("want 1 result, got %d", len(result.Results))
	}
	if result.Results[0].Status != "success" {
		t.Errorf("dry-run result status must be 'success', got %q", result.Results[0].Status)
	}
}

func TestDryRunExecutor_AuditTrail(t *testing.T) {
	exec := adapter.NewDryRunExecutor()
	batch := models.Batch{
		ID: "dry-2",
		Actions: []models.ExecutableOperation{
			{
				ExecutionID:       "e2",
				Type:              models.ActionDeleteDecision,
				StableIdentityKey: "ip:5.6.7.8",
				Scope:             "ip",
				Value:             "5.6.7.8",
				OriginatingOpID:   "op2",
			},
		},
	}

	result, _ := exec.Execute(context.Background(), batch)
	if result.Results[0].Audit.RawCommand != "(dry-run)" {
		t.Errorf("dry-run audit RawCommand must be '(dry-run)', got %q", result.Results[0].Audit.RawCommand)
	}
	if result.Results[0].Audit.ExecutedBy != "dry-run-executor" {
		t.Errorf("dry-run audit ExecutedBy must be 'dry-run-executor', got %q", result.Results[0].Audit.ExecutedBy)
	}
}

func TestDryRunExecutor_BatchIDPreserved(t *testing.T) {
	exec := adapter.NewDryRunExecutor()
	batch := models.Batch{ID: "batch-xyz", Actions: []models.ExecutableOperation{
		{ExecutionID: "e1", Type: models.ActionAddDecision, StableIdentityKey: "sik", Scope: "ip", Value: "1.2.3.4", OriginatingOpID: "op1"},
	}}
	result, _ := exec.Execute(context.Background(), batch)
	if result.BatchID != "batch-xyz" {
		t.Errorf("BatchID not preserved: got %q", result.BatchID)
	}
}

func TestDryRunExecutor_EmptyBatch(t *testing.T) {
	exec := adapter.NewDryRunExecutor()
	result, err := exec.Execute(context.Background(), models.Batch{ID: "empty"})
	if err != nil {
		t.Fatalf("empty batch error: %v", err)
	}
	if !result.Success {
		t.Error("empty batch must be Success=true")
	}
	if len(result.Results) != 0 {
		t.Errorf("empty batch must have 0 results, got %d", len(result.Results))
	}
}

// ── CSCLIExecutor unit tests (logic, not subprocess) ─────────────────────────

// TestCSCLIExecutor_UnsupportedActionType verifies that an unrecognised action
// type results in a failed status without spawning a process.
func TestCSCLIExecutor_UnsupportedActionType(t *testing.T) {
	exec := adapter.NewCSCLIExecutor("echo", 5*time.Second) // use "echo" as bin — won't be called

	batch := models.Batch{
		ID: "bad-action",
		Actions: []models.ExecutableOperation{
			{
				ExecutionID:       "e1",
				Type:              "unsupported_action_type",
				StableIdentityKey: "sik",
				Value:             "1.2.3.4",
				OriginatingOpID:   "op1",
			},
		},
	}

	result, err := exec.Execute(context.Background(), batch)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Success {
		t.Error("batch with unsupported action type must have Success=false")
	}
	if result.Results[0].Status != "failed" {
		t.Errorf("unsupported action must produce 'failed' status, got %q", result.Results[0].Status)
	}
	if result.Results[0].Error != "unsupported action type" {
		t.Errorf("unexpected error message: %q", result.Results[0].Error)
	}
}

// TestCSCLIExecutor_DefaultsApplied verifies NewCSCLIExecutor applies defaults.
func TestCSCLIExecutor_DefaultsApplied(t *testing.T) {
	// No panic, no nil pointer — just verify construction succeeds
	exec := adapter.NewCSCLIExecutor("", 0)
	if exec == nil {
		t.Fatal("expected non-nil executor")
	}
}

// TestDryRunExecutor_MultipleActions verifies results are created for each action.
func TestDryRunExecutor_MultipleActions(t *testing.T) {
	exec := adapter.NewDryRunExecutor()
	batch := models.Batch{
		ID: "multi",
		Actions: []models.ExecutableOperation{
			{ExecutionID: "e1", Type: models.ActionAddDecision, StableIdentityKey: "sik1", Scope: "ip", Value: "1.2.3.4", OriginatingOpID: "op1"},
			{ExecutionID: "e2", Type: models.ActionDeleteDecision, StableIdentityKey: "sik2", Scope: "ip", Value: "5.6.7.8", OriginatingOpID: "op2"},
			{ExecutionID: "e3", Type: models.ActionAddDecision, StableIdentityKey: "sik3", Scope: "range", Value: "10.0.0.0/24", OriginatingOpID: "op3"},
		},
	}
	result, err := exec.Execute(context.Background(), batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Results) != 3 {
		t.Errorf("want 3 results, got %d", len(result.Results))
	}
	for i, r := range result.Results {
		if r.Status != "success" {
			t.Errorf("result[%d].Status = %q, want 'success'", i, r.Status)
		}
	}
}

// TestDryRunExecutor_TimestampsSet verifies StartTime/EndTime are populated.
func TestDryRunExecutor_TimestampsSet(t *testing.T) {
	exec := adapter.NewDryRunExecutor()
	before := time.Now().UTC()
	result, _ := exec.Execute(context.Background(), models.Batch{ID: "ts", Actions: []models.ExecutableOperation{
		{ExecutionID: "e1", Type: models.ActionAddDecision, StableIdentityKey: "sik", Scope: "ip", Value: "1.2.3.4", OriginatingOpID: "op1"},
	}})
	after := time.Now().UTC()

	if result.StartTime.IsZero() {
		t.Error("StartTime must be set")
	}
	if result.EndTime.IsZero() {
		t.Error("EndTime must be set")
	}
	if result.StartTime.Before(before) || result.StartTime.After(after) {
		t.Error("StartTime outside expected window")
	}
}
