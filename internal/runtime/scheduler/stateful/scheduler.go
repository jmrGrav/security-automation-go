package stateful

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/observability/metrics"
	"github.com/jm/security-automation-go/internal/orchestrator/pipeline"
	"github.com/jm/security-automation-go/internal/runtime/cooldown"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/budget"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/pool"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/queue"
	"github.com/jm/security-automation-go/internal/runtime/scope"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

// Scheduler orchestrates periodic reconciliation runs.
type Scheduler struct {
	mu             sync.Mutex
	store          *state.StateStore
	orch           *pipeline.Orchestrator
	sm             *engine.StateMachine
	cooldown       *cooldown.Manager
	logger         *slog.Logger
	interval       time.Duration
	retryPolicy    RetryPolicy
	cooldownPolicy CooldownPolicy

	// Multi-worker components
	pool   *pool.Pool
	budget *budget.Manager
	queue  *queue.WorkQueue

	shutdown chan struct{}
	stopOnce sync.Once
}

func New(store *state.StateStore, orch *pipeline.Orchestrator, sm *engine.StateMachine, cm *cooldown.Manager, logger *slog.Logger, interval time.Duration) *Scheduler {
	bm := budget.NewManager()
	return &Scheduler{
		store:          store,
		orch:           orch,
		sm:             sm,
		cooldown:       cm,
		logger:         logger,
		interval:       interval,
		retryPolicy:    DefaultRetryPolicy(),
		cooldownPolicy: DefaultCooldownPolicy(),
		budget:         bm,
		pool:           pool.New(4, bm, logger),
		queue:          queue.New(),
		shutdown:       make(chan struct{}),
	}
}

// Start runs the main scheduler loop.
func (s *Scheduler) Start(ctx context.Context, zoneID string) error {
	s.logger.Info("starting stateful multi-worker scheduler", "interval", s.interval)

	if err := s.recoverStaleState(ctx); err != nil {
		s.logger.Warn("startup: stale state recovery failed (continuing)", "error", err)
	}

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Process queue in a dedicated loop
	go s.processQueue(ctx)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-s.shutdown:
			return nil
		case <-ticker.C:
			metrics.SchedulerRunsTotal.Inc()
			scopes, err := s.store.ListScopes()
			if err != nil {
				s.logger.Warn("failed to list scheduler scopes", "error", err)
				scopes = []string{zoneID}
			}
			if len(scopes) == 0 {
				scopes = []string{zoneID}
			}
			for _, scopedID := range scopes {
				s.queue.Push(models.WorkItem{
					Scope:    s.scopeForID(zoneID, scopedID),
					Priority: models.PriorityNormal,
					Type:     "reconcile",
				})
			}
		}
	}
}

func (s *Scheduler) processQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdown:
			return
		default:
			item, ok := s.queue.Pop()
			if !ok {
				time.Sleep(s.interval / 10)
				continue
			}

			if err := s.tick(ctx, item); err != nil {
				s.logger.Error("scheduler tick failed", "error", err, "scope", item.Scope.String())
			}
		}
	}
}

func (s *Scheduler) tick(ctx context.Context, item models.WorkItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	const op = "runtime.scheduler.stateful.tick"

	// 1. Load Scoped State
	curState, err := s.store.LoadForScope(item.Scope.ID())
	if err != nil {
		return err
	}

	// 2. Lifecycle & Cooldown checks (Simplified for multi-worker)
	status := curState.Lifecycle.Status
	if status == "" {
		status = models.StatusIdle
	}

	if status != models.StatusIdle && status != models.StatusConverged && status != models.StatusFailed {
		return nil
	}

	if s.cooldown.Remaining() > 0 {
		return nil
	}

	// 3. Prepare Runtime Context
	rtCtx := models.RuntimeContext{
		Context:      ctx,
		Scope:        item.Scope,
		FencingToken: curState.CurrentEpoch.Generation,
		Budget:       s.budget.GetBudget(item.Scope.Tenant),
	}

	// 4. Submit to pool
	s.pool.Submit(rtCtx, func(c models.RuntimeContext) error {
		// This runs inside a worker goroutine
		return s.executeRun(c)
	})

	return nil
}

func (s *Scheduler) executeRun(ctx models.RuntimeContext) error {
	// 1. Formal transition
	if err := s.sm.Transition(ctx, models.StatusDiscovering, "autonomous run"); err != nil {
		return err
	}

	// 2. Perform reconciliation through orchestrator
	// _, err := s.orch.DryRun(ctx, ctx.Scope.ZoneID, ...)

	// 3. Finalize
	_ = s.sm.Transition(ctx, models.StatusIdle, "run completed")
	return nil
}

func (s *Scheduler) scopeForID(zoneID string, scopeID string) scope.RuntimeScope {
	if scopeID == "" {
		return scope.RuntimeScope{
			Tenant:      "default",
			ZoneID:      zoneID,
			Environment: "prod",
		}
	}
	return scope.RuntimeScope{
		Tenant:      "default",
		AccountID:   scopeID,
		ZoneID:      zoneID,
		Environment: "prod",
	}
}

// recoverStaleState resets any non-terminal status left by a previous crash so
// the next tick can proceed via StatusFailed → StatusDiscovering.
// StatusPaused and StatusQuarantined are intentional operator states and are not reset.
func (s *Scheduler) recoverStaleState(ctx context.Context) error {
	curState, err := s.store.Load()
	if err != nil {
		return err
	}
	switch curState.Lifecycle.Status {
	case "",
		models.StatusIdle,
		models.StatusConverged,
		models.StatusFailed,
		models.StatusPaused,
		models.StatusQuarantined:
		return nil
	}
	s.logger.Warn("startup: stale non-terminal state detected, resetting to failed",
		"stale_status", curState.Lifecycle.Status)
	return s.sm.Transition(ctx, models.StatusFailed, "startup: stale state recovery")
}

func (s *Scheduler) GetPool() *pool.Pool {
	return s.pool
}

func (s *Scheduler) Stop() {
	s.stopOnce.Do(func() {
		close(s.shutdown)
		s.pool.Close()
	})
}
