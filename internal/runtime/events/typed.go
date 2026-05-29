package events

import (
	"time"

	rtmodels "github.com/jm/security-automation-go/internal/runtime/models"
)

const (
	TypeLifecycleTransition = "lifecycle_transition"
	TypePolicyDecision      = "policy_decision"
	TypeMutationPlanned     = "mutation_planned"
	TypeMutationApplied     = "mutation_applied"
	TypeRollbackStarted     = "rollback_started"
	TypeRollbackCompleted   = "rollback_completed"
	TypeRollbackFailed      = "rollback_failed"
	TypeDriftDetected       = "drift_detected"
	TypeLeaseAcquired       = "lease_acquired"
	TypeFencingTokenIssued  = "fencing_token_issued"
	TypeSchedulerTick       = "scheduler_tick"
	TypeWorkerStarted       = "worker_started"
	TypeWorkerStopped       = "worker_stopped"
	TypeGovernorPressure    = "governor_pressure"
	TypeBreakerOpened       = "breaker_opened"
	TypeBreakerClosed       = "breaker_closed"
	TypeHALeaderElected     = "ha_leader_elected"
	TypeHALeaderLost        = "ha_leader_lost"
	TypeRecoveryStarted     = "recovery_started"
	TypeRecoveryCompleted   = "recovery_completed"
	TypeReplayDivergence    = "replay_divergence_detected"
)

type Context struct {
	ScopeID       string
	CorrelationID string
	CausalID      string
	Actor         string
	Metadata      map[string]any
}

type LifecycleTransitionPayload struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Reason string `json:"reason"`
}

type PolicyDecisionPayload struct {
	PolicyID string `json:"policy_id"`
	Decision string `json:"decision"`
	Action   string `json:"action"`
	Reason   string `json:"reason"`
}

type MutationAppliedPayload struct {
	MutationID string `json:"mutation_id"`
	Target     string `json:"target"`
	Action     string `json:"action"`
	Status     string `json:"status"`
	LineageID  string `json:"lineage_id"`
}

type MutationPlannedPayload struct {
	MutationID string `json:"mutation_id"`
	Target     string `json:"target"`
	Action     string `json:"action"`
	Reason     string `json:"reason"`
	LineageID  string `json:"lineage_id"`
}

type RollbackPayload struct {
	RollbackID string `json:"rollback_id"`
	Reason     string `json:"reason"`
	LineageID  string `json:"lineage_id"`
}

type DriftDetectedPayload struct {
	Target   string `json:"target"`
	Severity string `json:"severity"`
	Diff     string `json:"diff"`
}

type LeaseAcquiredPayload struct {
	LeaseID      string    `json:"lease_id"`
	Action       string    `json:"action"`
	EpochID      string    `json:"epoch_id"`
	Owner        string    `json:"owner"`
	FencingToken int64     `json:"fencing_token"`
	ExpiresAt    time.Time `json:"expires_at"`
}

type FencingTokenIssuedPayload struct {
	EpochID      string `json:"epoch_id"`
	FencingToken int64  `json:"fencing_token"`
	Reason       string `json:"reason"`
}

type SchedulerTickPayload struct {
	ScopeID  string `json:"scope_id"`
	WorkType string `json:"work_type"`
	Priority int    `json:"priority"`
}

type WorkerLifecyclePayload struct {
	WorkerID string `json:"worker_id"`
	ScopeID  string `json:"scope_id"`
	Status   string `json:"status"`
}

type HALeaderPayload struct {
	NodeID string `json:"node_id"`
	Reason string `json:"reason"`
}

type GovernorPressurePayload struct {
	TenantID   string  `json:"tenant_id"`
	UsageRatio float64 `json:"usage_ratio"`
	Reason     string  `json:"reason"`
}

type BreakerStatePayload struct {
	State  string `json:"state"`
	Reason string `json:"reason"`
}

type RecoveryPayload struct {
	Mode       string    `json:"mode"`
	TargetTime time.Time `json:"target_time,omitempty"`
	TargetSeq  uint64    `json:"target_sequence,omitempty"`
	Reason     string    `json:"reason"`
}

type ReplayDivergencePayload struct {
	ExpectedChecksum string `json:"expected_checksum"`
	ActualChecksum   string `json:"actual_checksum"`
	Sequence         uint64 `json:"sequence"`
	Reason           string `json:"reason"`
}

func NewLifecycleTransition(ctx Context, from rtmodels.RuntimeStatus, to rtmodels.RuntimeStatus, reason string) PublishRequest {
	return request(CategoryLifecycle, TypeLifecycleTransition, ctx, LifecycleTransitionPayload{
		From:   from.String(),
		To:     to.String(),
		Reason: reason,
	})
}

func NewPolicyDecision(ctx Context, policyID string, decision string, action string, reason string) PublishRequest {
	return request(CategoryPolicy, TypePolicyDecision, ctx, PolicyDecisionPayload{
		PolicyID: policyID,
		Decision: decision,
		Action:   action,
		Reason:   reason,
	})
}

func NewMutationPlanned(ctx Context, mutationID string, target string, action string, reason string, lineageID string) PublishRequest {
	ctx.Metadata = withLineage(ctx.Metadata, lineageID, "")
	return request(CategoryMutation, TypeMutationPlanned, ctx, MutationPlannedPayload{
		MutationID: mutationID,
		Target:     target,
		Action:     action,
		Reason:     reason,
		LineageID:  lineageID,
	})
}

func NewMutationApplied(ctx Context, mutationID string, target string, action string, status string, lineageID string) PublishRequest {
	ctx.Metadata = withLineage(ctx.Metadata, lineageID, "")
	return request(CategoryMutation, TypeMutationApplied, ctx, MutationAppliedPayload{
		MutationID: mutationID,
		Target:     target,
		Action:     action,
		Status:     status,
		LineageID:  lineageID,
	})
}

func NewRollbackStarted(ctx Context, rollbackID string, reason string, lineageID string) PublishRequest {
	ctx.Metadata = withLineage(ctx.Metadata, "", lineageID)
	return request(CategoryRollback, TypeRollbackStarted, ctx, RollbackPayload{
		RollbackID: rollbackID,
		Reason:     reason,
		LineageID:  lineageID,
	})
}

func NewRollbackCompleted(ctx Context, rollbackID string, reason string, lineageID string) PublishRequest {
	ctx.Metadata = withLineage(ctx.Metadata, "", lineageID)
	return request(CategoryRollback, TypeRollbackCompleted, ctx, RollbackPayload{
		RollbackID: rollbackID,
		Reason:     reason,
		LineageID:  lineageID,
	})
}

func NewRollbackFailed(ctx Context, rollbackID string, reason string, lineageID string) PublishRequest {
	ctx.Metadata = withLineage(ctx.Metadata, "", lineageID)
	return request(CategoryRollback, TypeRollbackFailed, ctx, RollbackPayload{
		RollbackID: rollbackID,
		Reason:     reason,
		LineageID:  lineageID,
	})
}

func NewDriftDetected(ctx Context, target string, severity string, diff string) PublishRequest {
	return request(CategoryDrift, TypeDriftDetected, ctx, DriftDetectedPayload{
		Target:   target,
		Severity: severity,
		Diff:     diff,
	})
}

func NewLeaseAcquired(ctx Context, leaseID string, action string, epochID string, owner string, fencingToken int64, expiresAt time.Time) PublishRequest {
	return request(CategoryLease, TypeLeaseAcquired, ctx, LeaseAcquiredPayload{
		LeaseID:      leaseID,
		Action:       action,
		EpochID:      epochID,
		Owner:        owner,
		FencingToken: fencingToken,
		ExpiresAt:    expiresAt.UTC(),
	})
}

func NewFencingTokenIssued(ctx Context, epochID string, fencingToken int64, reason string) PublishRequest {
	return request(CategoryFencing, TypeFencingTokenIssued, ctx, FencingTokenIssuedPayload{
		EpochID:      epochID,
		FencingToken: fencingToken,
		Reason:       reason,
	})
}

func NewSchedulerTick(ctx Context, workType string, priority int) PublishRequest {
	return request(CategoryScheduler, TypeSchedulerTick, ctx, SchedulerTickPayload{
		ScopeID:  ctx.ScopeID,
		WorkType: workType,
		Priority: priority,
	})
}

func NewWorkerStarted(ctx Context, workerID string) PublishRequest {
	return request(CategoryScheduler, TypeWorkerStarted, ctx, WorkerLifecyclePayload{
		WorkerID: workerID,
		ScopeID:  ctx.ScopeID,
		Status:   "started",
	})
}

func NewWorkerStopped(ctx Context, workerID string) PublishRequest {
	return request(CategoryScheduler, TypeWorkerStopped, ctx, WorkerLifecyclePayload{
		WorkerID: workerID,
		ScopeID:  ctx.ScopeID,
		Status:   "stopped",
	})
}

func NewGovernorPressure(ctx Context, tenantID string, usageRatio float64, reason string) PublishRequest {
	return request(CategoryScheduler, TypeGovernorPressure, ctx, GovernorPressurePayload{
		TenantID:   tenantID,
		UsageRatio: usageRatio,
		Reason:     reason,
	})
}

func NewBreakerOpened(ctx Context, reason string) PublishRequest {
	return request(CategorySecurity, TypeBreakerOpened, ctx, BreakerStatePayload{
		State:  "open",
		Reason: reason,
	})
}

func NewBreakerClosed(ctx Context, reason string) PublishRequest {
	return request(CategorySecurity, TypeBreakerClosed, ctx, BreakerStatePayload{
		State:  "closed",
		Reason: reason,
	})
}

func NewLeaderElected(ctx Context, nodeID string, reason string) PublishRequest {
	return request(CategoryHA, TypeHALeaderElected, ctx, HALeaderPayload{
		NodeID: nodeID,
		Reason: reason,
	})
}

func NewLeaderLost(ctx Context, nodeID string, reason string) PublishRequest {
	return request(CategoryHA, TypeHALeaderLost, ctx, HALeaderPayload{
		NodeID: nodeID,
		Reason: reason,
	})
}

func NewRecoveryStarted(ctx Context, mode string, targetTime time.Time, targetSeq uint64, reason string) PublishRequest {
	return request(CategoryLifecycle, TypeRecoveryStarted, ctx, RecoveryPayload{
		Mode:       mode,
		TargetTime: targetTime.UTC(),
		TargetSeq:  targetSeq,
		Reason:     reason,
	})
}

func NewRecoveryCompleted(ctx Context, mode string, targetTime time.Time, targetSeq uint64, reason string) PublishRequest {
	return request(CategoryLifecycle, TypeRecoveryCompleted, ctx, RecoveryPayload{
		Mode:       mode,
		TargetTime: targetTime.UTC(),
		TargetSeq:  targetSeq,
		Reason:     reason,
	})
}

func NewReplayDivergenceDetected(ctx Context, expectedChecksum string, actualChecksum string, sequence uint64, reason string) PublishRequest {
	return request(CategorySecurity, TypeReplayDivergence, ctx, ReplayDivergencePayload{
		ExpectedChecksum: expectedChecksum,
		ActualChecksum:   actualChecksum,
		Sequence:         sequence,
		Reason:           reason,
	})
}

func request(category Category, eventType string, ctx Context, payload any) PublishRequest {
	return PublishRequest{
		Category:      category,
		Type:          eventType,
		ScopeID:       ctx.ScopeID,
		CorrelationID: ctx.CorrelationID,
		CausalID:      ctx.CausalID,
		Actor:         ctx.Actor,
		Payload:       payload,
		Metadata:      cloneMap(ctx.Metadata),
	}
}

func withLineage(metadata map[string]any, mutationLineageID string, rollbackLineageID string) map[string]any {
	out := cloneMap(metadata)
	if mutationLineageID != "" {
		out["mutation_lineage_id"] = mutationLineageID
	}
	if rollbackLineageID != "" {
		out["rollback_lineage_id"] = rollbackLineageID
	}
	return out
}

func cloneMap(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}
