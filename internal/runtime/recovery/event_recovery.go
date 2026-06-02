package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/runtime/checkpoint"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/reducer"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

type IntegrityChecker interface {
	IntegrityCheck(ctx context.Context) error
}

type RecoveryOptions struct {
	ScopeID        string
	DryRun         bool
	TargetSequence uint64
	TargetTime     time.Time
	Reason         string
}

type RecoveryReport struct {
	ScopeID                     string              `json:"scope_id"`
	RecoveredState              models.RuntimeState `json:"recovered_state"`
	CheckpointSequence          uint64              `json:"checkpoint_sequence"`
	FinalSequence               uint64              `json:"final_sequence"`
	EventsApplied               uint64              `json:"events_applied"`
	UsedCheckpoint              bool                `json:"used_checkpoint"`
	OrphanLeaseDetected         bool                `json:"orphan_lease_detected"`
	ZombieEpochDetected         bool                `json:"zombie_epoch_detected"`
	DivergenceDetected          bool                `json:"divergence_detected"`
	Checksum                    string              `json:"checksum"`
	Mode                        string              `json:"mode"`
	Plan                        RecoveryPlan        `json:"plan"`
	OwnershipInvariantViolation bool                `json:"ownership_invariant_violation"`
	OwnershipInvariantIssues    []string            `json:"ownership_invariant_issues,omitempty"`
}

type RecoveryPlan struct {
	ScopeID            string    `json:"scope_id"`
	Mode               string    `json:"mode"`
	TargetSequence     uint64    `json:"target_sequence,omitempty"`
	TargetTime         time.Time `json:"target_time,omitempty"`
	CheckpointName     string    `json:"checkpoint_name"`
	ResumeFromSequence uint64    `json:"resume_from_sequence"`
	Reason             string    `json:"reason,omitempty"`
}

type RecoveryManifest struct {
	Plan               RecoveryPlan `json:"plan"`
	GeneratedAt        time.Time    `json:"generated_at"`
	UsedCheckpoint     bool         `json:"used_checkpoint"`
	CheckpointSequence uint64       `json:"checkpoint_sequence"`
	Checksum           string       `json:"checksum"`
}

type EventEngine struct {
	checkpoints *checkpoint.Manager
	eventStore  events.EventStore
	stateStore  *state.StateStore
	leaseStore  interface {
		GetActiveLease(ctx context.Context, scopeID string, action string) (*models.Lease, error)
	}
	integrity      IntegrityChecker
	ownershipStore interface {
		ListClaims(ctx context.Context) ([]ownership.OwnershipClaim, error)
		ListLineage(ctx context.Context, scopeID string, resourceID string, limit int) ([]ownership.LineageEvent, error)
	}
}

func NewEventEngine(checkpoints *checkpoint.Manager, eventStore events.EventStore, stateStore *state.StateStore, leaseStore interface {
	GetActiveLease(ctx context.Context, scopeID string, action string) (*models.Lease, error)
}, integrity IntegrityChecker) *EventEngine {
	return &EventEngine{
		checkpoints: checkpoints,
		eventStore:  eventStore,
		stateStore:  stateStore,
		leaseStore:  leaseStore,
		integrity:   integrity,
	}
}

func (e *EventEngine) SetOwnershipStore(store interface {
	ListClaims(ctx context.Context) ([]ownership.OwnershipClaim, error)
	ListLineage(ctx context.Context, scopeID string, resourceID string, limit int) ([]ownership.LineageEvent, error)
}) {
	e.ownershipStore = store
}

func (e *EventEngine) Recover(ctx context.Context, opts RecoveryOptions) (RecoveryReport, error) {
	const op = "runtime.recovery.EventEngine.Recover"

	if e.integrity != nil {
		if err := e.integrity.IntegrityCheck(ctx); err != nil {
			return RecoveryReport{}, apperr.Wrap(op, err)
		}
	}
	if e.checkpoints != nil {
		if err := e.checkpoints.InvalidateStale(ctx, opts.ScopeID, checkpoint.DefaultRuntimeCheckpointName); err != nil {
			return RecoveryReport{}, apperr.Wrap(op, err)
		}
	}

	plan, manifest, err := e.Plan(ctx, opts)
	if err != nil {
		return RecoveryReport{}, apperr.Wrap(op, err)
	}

	replayer := &runtimeStateReplayer{}
	result, err := events.ReplayWithOptions(ctx, e.eventStore, opts.ScopeID, replayer, events.ReplayOptions{
		CheckpointName: checkpoint.DefaultRuntimeCheckpointName,
		UntilSequence:  opts.TargetSequence,
		UntilTime:      opts.TargetTime,
	})
	if err != nil {
		return RecoveryReport{}, apperr.Wrap(op, err)
	}

	report := RecoveryReport{
		ScopeID:            opts.ScopeID,
		RecoveredState:     replayer.state,
		CheckpointSequence: result.StartedAfterSequence,
		FinalSequence:      result.FinalSequence,
		EventsApplied:      result.EventsApplied,
		UsedCheckpoint:     result.UsedCheckpoint,
		Checksum:           manifest.Checksum,
		Mode:               plan.Mode,
		Plan:               plan,
	}
	report.OrphanLeaseDetected, report.ZombieEpochDetected = e.detectLeaseAndEpochAnomalies(ctx, opts.ScopeID, replayer.state)
	report.OwnershipInvariantViolation, report.OwnershipInvariantIssues = e.detectOwnershipInvariants(ctx, opts.ScopeID)
	if report.OwnershipInvariantViolation {
		metrics.RuntimeOwnershipInvariantViolationsTotal.Inc()
		return report, apperr.Newf(op, "ownership invariants violated: %v", report.OwnershipInvariantIssues)
	}

	current, err := e.stateStore.Load()
	if err != nil {
		return RecoveryReport{}, apperr.Wrap(op, err)
	}
	report.DivergenceDetected = !runtimeStatesEqual(current, replayer.state)
	if report.DivergenceDetected {
		metrics.RuntimeRecoveryDivergencesTotal.Inc()
	}

	if !opts.DryRun {
		if err := e.stateStore.Save(replayer.state); err != nil {
			return RecoveryReport{}, apperr.Wrap(op, err)
		}
	}

	return report, nil
}

func (e *EventEngine) Plan(ctx context.Context, opts RecoveryOptions) (RecoveryPlan, RecoveryManifest, error) {
	const op = "runtime.recovery.EventEngine.Plan"

	plan := RecoveryPlan{
		ScopeID:        opts.ScopeID,
		CheckpointName: checkpoint.DefaultRuntimeCheckpointName,
		TargetSequence: opts.TargetSequence,
		TargetTime:     opts.TargetTime.UTC(),
		Reason:         opts.Reason,
		Mode:           recoveryMode(opts),
	}

	var checkpointSequence uint64
	var usedCheckpoint bool
	if e.checkpoints != nil {
		state, cp, err := e.checkpoints.LatestRuntimeState(ctx, opts.ScopeID)
		switch {
		case err == nil:
			_ = state
			checkpointSequence = cp.Sequence
			plan.ResumeFromSequence = cp.Sequence
			usedCheckpoint = true
		case err == events.ErrCheckpointNotFound:
		default:
			return RecoveryPlan{}, RecoveryManifest{}, apperr.Wrap(op, err)
		}
	}
	if opts.TargetSequence > 0 && checkpointSequence > opts.TargetSequence {
		plan.ResumeFromSequence = 0
		usedCheckpoint = false
		checkpointSequence = 0
	}
	if !opts.TargetTime.IsZero() {
		plan.ResumeFromSequence = 0
		usedCheckpoint = false
		checkpointSequence = 0
	}

	manifest := RecoveryManifest{
		Plan:               plan,
		GeneratedAt:        time.Now().UTC(),
		UsedCheckpoint:     usedCheckpoint,
		CheckpointSequence: checkpointSequence,
	}
	manifest.Checksum = manifestChecksum(manifest)
	return plan, manifest, nil
}

func (e *EventEngine) detectLeaseAndEpochAnomalies(ctx context.Context, scopeID string, state models.RuntimeState) (bool, bool) {
	var orphanLease bool
	if e.leaseStore != nil {
		for _, action := range []string{"reconcile", "rollback"} {
			lease, err := e.leaseStore.GetActiveLease(ctx, scopeID, action)
			if err == nil && lease != nil && state.ActiveLease == nil && state.ActiveRollbackLease == nil {
				orphanLease = true
				break
			}
		}
	}

	zombieEpoch := state.CurrentEpoch.Generation > 0 &&
		state.Lifecycle.Status != models.StatusIdle &&
		state.Lifecycle.Status != models.StatusConverged &&
		state.Lifecycle.Status != models.StatusFailed &&
		state.ActiveLease == nil &&
		state.ActiveRollbackLease == nil

	return orphanLease, zombieEpoch
}

func (e *EventEngine) detectOwnershipInvariants(ctx context.Context, scopeID string) (bool, []string) {
	if e.ownershipStore == nil {
		return false, nil
	}
	claims, err := e.ownershipStore.ListClaims(ctx)
	if err != nil {
		return true, []string{"ownership_claims_unavailable"}
	}
	issues := make([]string, 0)
	for _, claim := range claims {
		if claim.ScopeID != scopeID {
			continue
		}
		if claim.DomainID == "" {
			issues = append(issues, "claim_missing_domain:"+claim.ResourceID)
		}
		if claim.ResourceID == "" {
			issues = append(issues, "claim_missing_resource")
		}
		if claim.Epoch <= 0 {
			issues = append(issues, "claim_non_positive_epoch:"+claim.ResourceID)
		}
		lineage, lerr := e.ownershipStore.ListLineage(ctx, claim.ScopeID, claim.ResourceID, 1)
		if lerr != nil {
			issues = append(issues, "lineage_unavailable:"+claim.ResourceID)
			continue
		}
		if len(lineage) == 0 {
			issues = append(issues, "lineage_missing:"+claim.ResourceID)
			continue
		}
		latest := lineage[0]
		if latest.EventType != ownership.LineageEventClaim {
			issues = append(issues, "lineage_latest_not_claim:"+claim.ResourceID)
		}
		if latest.Epoch != claim.Epoch {
			issues = append(issues, "lineage_epoch_mismatch:"+claim.ResourceID)
		}
		if latest.DomainID != claim.DomainID {
			issues = append(issues, "lineage_domain_mismatch:"+claim.ResourceID)
		}
	}
	return len(issues) > 0, issues
}

type runtimeStateReplayer struct {
	state models.RuntimeState
}

func (r *runtimeStateReplayer) RestoreCheckpoint(_ context.Context, checkpoint events.Checkpoint) error {
	return json.Unmarshal(checkpoint.State, &r.state)
}

func (r *runtimeStateReplayer) ApplyEvent(_ context.Context, event events.Event) error {
	next, err := reducer.ApplyEvent(r.state, event)
	if err != nil {
		return err
	}
	r.state = next
	return nil
}

func runtimeStatesEqual(left models.RuntimeState, right models.RuntimeState) bool {
	leftBytes, _ := json.Marshal(left)
	rightBytes, _ := json.Marshal(right)
	return string(leftBytes) == string(rightBytes)
}

func manifestChecksum(manifest RecoveryManifest) string {
	payload, _ := json.Marshal(manifest.Plan)
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func recoveryMode(opts RecoveryOptions) string {
	switch {
	case opts.TargetSequence > 0:
		return "sequence"
	case !opts.TargetTime.IsZero():
		return "time"
	default:
		return "latest"
	}
}

func (r RecoveryReport) String() string {
	return fmt.Sprintf("scope=%s mode=%s checkpoint=%d final=%d applied=%d divergence=%t", r.ScopeID, r.Mode, r.CheckpointSequence, r.FinalSequence, r.EventsApplied, r.DivergenceDetected)
}
