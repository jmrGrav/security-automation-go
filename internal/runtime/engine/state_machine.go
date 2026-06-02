package engine

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/reducer"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

// StateMachine manages formal runtime lifecycle transitions.
type StateMachine struct {
	mu       sync.Mutex
	store    *state.StateStore
	logger   *slog.Logger
	eventBus interface {
		PublishEvent(ctx context.Context, req events.PublishRequest) (events.Event, error)
	}
	checkpoints interface {
		SaveRuntimeState(ctx context.Context, scopeID string, trigger string, event events.Event, state models.RuntimeState) (events.Checkpoint, error)
		SaveNamedRuntimeState(ctx context.Context, name string, scopeID string, trigger string, event events.Event, state models.RuntimeState) (events.Checkpoint, error)
	}
}

func NewStateMachine(store *state.StateStore, logger *slog.Logger) *StateMachine {
	return &StateMachine{
		store:  store,
		logger: logger,
	}
}

func (m *StateMachine) SetEventBus(bus interface {
	PublishEvent(ctx context.Context, req events.PublishRequest) (events.Event, error)
}) {
	m.eventBus = bus
}

func (m *StateMachine) SetCheckpointManager(manager interface {
	SaveRuntimeState(ctx context.Context, scopeID string, trigger string, event events.Event, state models.RuntimeState) (events.Checkpoint, error)
	SaveNamedRuntimeState(ctx context.Context, name string, scopeID string, trigger string, event events.Event, state models.RuntimeState) (events.Checkpoint, error)
}) {
	m.checkpoints = manager
}

// Transition attempts to move the runtime state to a new status.
func (m *StateMachine) Transition(ctx context.Context, to models.RuntimeStatus, reason string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	const op = "runtime.engine.Transition"

	curState, err := m.store.Load()
	if err != nil {
		return apperr.Wrap(op, err)
	}

	from := curState.Lifecycle.Status
	if from == "" {
		from = models.StatusIdle
	}

	if !m.isTransitionAllowed(from, to) {
		return apperr.Newf(op, "invalid transition from %s to %s", from, to)
	}

	m.logger.Info("lifecycle_transition", "from", from, "to", to, "reason", reason)

	rtCtx, _ := ctx.(models.RuntimeContext)
	now := time.Now().UTC()
	curState = reducer.ApplyLifecycleTransition(curState, reducer.TransitionInput{
		From:         from,
		To:           to,
		At:           now,
		EpochID:      rtCtx.EpochID,
		FencingToken: rtCtx.FencingToken,
		LeaseID:      rtCtx.LeaseID,
	})

	if err := m.store.Save(curState); err != nil {
		return apperr.Wrap(op, err)
	}

	if m.eventBus != nil {
		scopeID := "default"
		correlationID := curState.LastRunID
		actor := "runtime-state-machine"
		if rtCtx.Scope.ID() != "" {
			scopeID = rtCtx.Scope.ID()
		}
		if rtCtx.TraceID != "" {
			correlationID = rtCtx.TraceID
		}
		event, err := m.eventBus.PublishEvent(ctx, events.NewLifecycleTransition(events.Context{
			ScopeID:       scopeID,
			CorrelationID: correlationID,
			Actor:         actor,
			Metadata: map[string]any{
				"reason":        reason,
				"epoch_id":      rtCtx.EpochID,
				"fencing_token": rtCtx.FencingToken,
				"lease_id":      rtCtx.LeaseID,
				"trace_id":      rtCtx.TraceID,
			},
		}, from, to, reason))
		if err != nil {
			return apperr.Wrap(op, err)
		}
		if m.checkpoints != nil {
			trigger := "transition:" + to.String()
			if _, err := m.checkpoints.SaveRuntimeState(ctx, scopeID, trigger, event, curState); err != nil {
				return apperr.Wrap(op, err)
			}
			switch to {
			case models.StatusRollingBack:
				if _, err := m.checkpoints.SaveNamedRuntimeState(ctx, "rollback-before", scopeID, trigger, event, curState); err != nil {
					return apperr.Wrap(op, err)
				}
			case models.StatusConverged:
				if _, err := m.checkpoints.SaveNamedRuntimeState(ctx, "post-convergence", scopeID, trigger, event, curState); err != nil {
					return apperr.Wrap(op, err)
				}
			}
			if from == models.StatusRollingBack && to == models.StatusIdle {
				if _, err := m.checkpoints.SaveNamedRuntimeState(ctx, "rollback-after", scopeID, "transition:rollback_after", event, curState); err != nil {
					return apperr.Wrap(op, err)
				}
			}
		}
	}

	return nil
}

func (m *StateMachine) isTransitionAllowed(from, to models.RuntimeStatus) bool {
	// Formal transition rules
	allowed := map[models.RuntimeStatus][]models.RuntimeStatus{
		models.StatusIdle: {
			models.StatusDiscovering,
			models.StatusQuarantined,
		},
		models.StatusDiscovering: {
			models.StatusPlanning,
			models.StatusQuarantined,
			models.StatusFailed,
		},
		models.StatusPlanning: {
			models.StatusAwaitingApproval,
			models.StatusExecuting,
			models.StatusQuarantined,
			models.StatusFailed,
		},
		models.StatusAwaitingApproval: {
			models.StatusExecuting,
			models.StatusIdle, // Rejected
			models.StatusQuarantined,
			models.StatusFailed,
		},
		models.StatusExecuting: {
			models.StatusValidating,
			models.StatusRollbackRequired,
			models.StatusQuarantined,
			models.StatusFailed,
		},
		models.StatusValidating: {
			models.StatusConverged,
			models.StatusRollbackRequired,
			models.StatusQuarantined,
			models.StatusFailed,
		},
		models.StatusConverged: {
			models.StatusIdle,
			models.StatusDiscovering, // Re-run
			models.StatusQuarantined,
		},
		models.StatusRollbackRequired: {
			models.StatusRollingBack,
			models.StatusFailed,
		},
		models.StatusRollingBack: {
			models.StatusIdle, // Successfully rolled back to stable state
			models.StatusQuarantined,
			models.StatusFailed,
		},
		models.StatusFailed: {
			models.StatusIdle,
			models.StatusDiscovering, // Retry
			models.StatusQuarantined,
		},
		models.StatusQuarantined: {
			models.StatusIdle, // Manual release
			models.StatusDiscovering,
		},
		models.StatusPaused: {
			models.StatusIdle,
			models.StatusDiscovering,
			models.StatusQuarantined,
		},
	}

	targets, ok := allowed[from]
	if !ok {
		return false
	}

	// Allow transition to Paused from almost anywhere stable
	if to == models.StatusPaused {
		return from == models.StatusIdle || from == models.StatusConverged || from == models.StatusFailed
	}

	for _, t := range targets {
		if t == to {
			return true
		}
	}

	return false
}
