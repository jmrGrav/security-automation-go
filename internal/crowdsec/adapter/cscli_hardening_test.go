package adapter_test

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/crowdsec/adapter"
	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// runOne executes a single operation through the CSCLIExecutor and returns the
// per-operation result. The executor delegates to crowdsec.Client; it must not
// spawn its own process.
func runOne(t *testing.T, binPath string, ctx context.Context, op models.ExecutableOperation) models.ExecutionResult {
	t.Helper()
	exec := adapter.NewCSCLIExecutor(binPath, 5*time.Second)
	res, err := exec.Execute(ctx, models.Batch{ID: "b", Actions: []models.ExecutableOperation{op}})
	if err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if len(res.Results) != 1 {
		t.Fatalf("want 1 result, got %d", len(res.Results))
	}
	return res.Results[0]
}

func validAdd() models.ExecutableOperation {
	return models.ExecutableOperation{
		ExecutionID: "e1", Type: models.ActionAddDecision, StableIdentityKey: "sik",
		Scope: "ip", Value: "1.2.3.4", Duration: "4h", Reason: "test", OriginatingOpID: "op1",
	}
}

// ── valid inputs pass validation and reach the delegated writer ──────────────

func TestCSCLIGuard_ValidIPAddReachesWriter(t *testing.T) {
	// "true" is used by the delegated crowdsec.Client runner; success proves
	// validation passed without CSCLIExecutor owning a direct os/exec path.
	res := runOne(t, "true", context.Background(), validAdd())
	if res.Status != "success" {
		t.Fatalf("valid IP add should succeed, got status=%q err=%q", res.Status, res.Error)
	}
}

func TestCSCLIGuard_ValidCIDRAddReachesWriter(t *testing.T) {
	op := validAdd()
	op.Scope = "range"
	op.Value = "10.0.0.0/24"
	op.Duration = "24h"
	res := runOne(t, "true", context.Background(), op)
	if res.Status != "success" {
		t.Fatalf("valid CIDR add should succeed, got status=%q err=%q", res.Status, res.Error)
	}
}

func TestCSCLIGuard_ValidDeleteReachesWriter(t *testing.T) {
	op := models.ExecutableOperation{
		ExecutionID: "e2", Type: models.ActionDeleteDecision, StableIdentityKey: "sik",
		Scope: "ip", Value: "5.6.7.8", OriginatingOpID: "op2",
	}
	res := runOne(t, "true", context.Background(), op)
	if res.Status != "success" {
		t.Fatalf("valid delete should succeed, got status=%q err=%q", res.Status, res.Error)
	}
}

// ── invalid inputs fail closed BEFORE delegation ──────────────────────────────
//
// The bin path points to a non-existent binary. If validation did not
// short-circuit, the delegated writer would return an exec error ("file not
// found"), not the specific validation reason asserted below.

const bogusBin = "/nonexistent/cscli-should-never-run"

func assertFailClosed(t *testing.T, op models.ExecutableOperation, wantErr string) {
	t.Helper()
	res := runOne(t, bogusBin, context.Background(), op)
	if res.Status != "failed" {
		t.Fatalf("expected failed status, got %q", res.Status)
	}
	if res.Error != wantErr {
		t.Fatalf("expected fail-closed reason %q (proving no process spawned), got %q", wantErr, res.Error)
	}
}

func TestCSCLIGuard_InvalidIP(t *testing.T) {
	op := validAdd()
	op.Value = "not-an-ip"
	assertFailClosed(t, op, "value is not a valid IP address")
}

func TestCSCLIGuard_InvalidCIDR(t *testing.T) {
	op := validAdd()
	op.Scope = "range"
	op.Value = "10.0.0.0/99"
	assertFailClosed(t, op, "value is not a valid CIDR range")
}

func TestCSCLIGuard_ForbiddenScope(t *testing.T) {
	op := validAdd()
	op.Scope = "country"
	op.Value = "FR"
	assertFailClosed(t, op, "invalid scope (allowed: ip, range)")
}

func TestCSCLIGuard_ForbiddenAction(t *testing.T) {
	op := validAdd()
	op.Type = "drop_everything"
	assertFailClosed(t, op, "unsupported action type")
}

func TestCSCLIGuard_FlagInjectionLeadingDash(t *testing.T) {
	op := validAdd()
	op.Scope = "ip"
	op.Value = "-rf"
	// ParseIP would also reject "-rf", but the leading-dash guard fires first
	// and is the security-relevant assertion.
	assertFailClosed(t, op, "argument must not start with '-'")
}

func TestCSCLIGuard_FlagInjectionInReason(t *testing.T) {
	op := validAdd()
	op.Reason = "--malicious-flag"
	assertFailClosed(t, op, "argument must not start with '-'")
}

func TestCSCLIGuard_EmptyValue(t *testing.T) {
	op := validAdd()
	op.Value = ""
	assertFailClosed(t, op, "missing target value")
}

func TestCSCLIGuard_EmptyDurationForAdd(t *testing.T) {
	op := validAdd()
	op.Duration = ""
	assertFailClosed(t, op, "missing duration for add decision")
}

func TestCSCLIGuard_InvalidDurationFormat(t *testing.T) {
	op := validAdd()
	op.Duration = "forever"
	assertFailClosed(t, op, "invalid duration format (expected e.g. 4h, 30m)")
}

// ── context cancellation is honored (no successful mutation) ──────────────────

func TestCSCLIGuard_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// Valid op so validation passes; cancelled context must prevent a
	// successful execution.
	res := runOne(t, "true", ctx, validAdd())
	if res.Status == "success" {
		t.Fatalf("cancelled context must not yield success")
	}
}
