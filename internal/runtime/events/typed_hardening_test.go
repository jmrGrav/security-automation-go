package events

import (
	"testing"
	"time"

	rtmodels "github.com/jm/security-automation-go/internal/runtime/models"
)

func TestNewLeaseAcquiredNormalizesTimestampAndFields(t *testing.T) {
	ctx := Context{ScopeID: "scope-a", Actor: "tester"}
	ts := time.Date(2026, 6, 1, 18, 0, 0, 0, time.FixedZone("CEST", 2*60*60))

	req := NewLeaseAcquired(ctx, "lease-1", "reconcile", "epoch-1", "owner-a", 17, ts)
	if req.Category != CategoryLease || req.Type != TypeLeaseAcquired {
		t.Fatalf("unexpected request classification: %+v", req)
	}
	payload, ok := req.Payload.(LeaseAcquiredPayload)
	if !ok {
		t.Fatalf("expected lease payload, got %T", req.Payload)
	}
	if !payload.ExpiresAt.Equal(ts.UTC()) {
		t.Fatalf("expected expires_at to be normalized to UTC, got %s want %s", payload.ExpiresAt, ts.UTC())
	}
	if payload.FencingToken != 17 || payload.EpochID != "epoch-1" || payload.Action != "reconcile" {
		t.Fatalf("unexpected lease payload: %+v", payload)
	}
}

func TestRollbackLifecycleEventsCarryLineageMetadata(t *testing.T) {
	ctx := Context{ScopeID: "scope-a", Actor: "tester", Metadata: map[string]any{"source": "operator"}}

	rollback := NewRollbackStarted(ctx, "rb-1", "manual rollback", "lineage-rb")
	if rollback.Category != CategoryRollback || rollback.Type != TypeRollbackStarted {
		t.Fatalf("unexpected rollback request: %+v", rollback)
	}
	if got := rollback.Metadata["rollback_lineage_id"]; got != "lineage-rb" {
		t.Fatalf("expected rollback lineage metadata, got %+v", rollback.Metadata)
	}
	payload, ok := rollback.Payload.(RollbackPayload)
	if !ok {
		t.Fatalf("expected rollback payload, got %T", rollback.Payload)
	}
	if payload.LineageID != "lineage-rb" || payload.RollbackID != "rb-1" {
		t.Fatalf("unexpected rollback payload: %+v", payload)
	}

	recovery := NewRecoveryCompleted(ctx, "restore", time.Date(2026, 6, 1, 18, 0, 0, 0, time.UTC), 9, "done")
	if recovery.Category != CategoryLifecycle || recovery.Type != TypeRecoveryCompleted {
		t.Fatalf("unexpected recovery request: %+v", recovery)
	}
	recoveryPayload, ok := recovery.Payload.(RecoveryPayload)
	if !ok {
		t.Fatalf("expected recovery payload, got %T", recovery.Payload)
	}
	if recoveryPayload.TargetSeq != 9 || recoveryPayload.Mode != "restore" || recoveryPayload.TargetTime.IsZero() {
		t.Fatalf("unexpected recovery payload: %+v", recoveryPayload)
	}
}

func TestLifecycleTransitionAndPolicyDecisionCarryTypedPayloads(t *testing.T) {
	ctx := Context{ScopeID: "scope-a", Actor: "tester"}
	lifecycle := NewLifecycleTransition(ctx, rtmodels.StatusIdle, rtmodels.StatusConverged, "ok")
	lifecyclePayload, ok := lifecycle.Payload.(LifecycleTransitionPayload)
	if !ok {
		t.Fatalf("expected lifecycle payload, got %T", lifecycle.Payload)
	}
	if lifecyclePayload.From != rtmodels.StatusIdle.String() || lifecyclePayload.To != rtmodels.StatusConverged.String() {
		t.Fatalf("unexpected lifecycle payload: %+v", lifecyclePayload)
	}

	policy := NewPolicyDecision(ctx, "policy-a", "allow", "propagable_ban", "reason")
	policyPayload, ok := policy.Payload.(PolicyDecisionPayload)
	if !ok {
		t.Fatalf("expected policy payload, got %T", policy.Payload)
	}
	if policyPayload.PolicyID != "policy-a" || policyPayload.Decision != "allow" || policyPayload.Action != "propagable_ban" {
		t.Fatalf("unexpected policy payload: %+v", policyPayload)
	}
}
