package pool

import (
	"context"
	"log/slog"
	"sync"

	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/budget"
)

type TaskFunc func(ctx models.RuntimeContext) error

// Pool manages a bounded set of workers for multi-scope orchestration.
type Pool struct {
	mu      sync.Mutex
	workers int
	active  int
	budget  *budget.Manager
	logger  *slog.Logger
	tasks   chan taskWrapper
	wg      sync.WaitGroup
	once    sync.Once
}

type taskWrapper struct {
	ctx  models.RuntimeContext
	fn   TaskFunc
	done chan error
}

func New(workers int, b *budget.Manager, logger *slog.Logger) *Pool {
	p := &Pool{
		workers: workers,
		budget:  b,
		logger:  logger,
		tasks:   make(chan taskWrapper, workers),
	}
	p.start()
	return p
}

func (p *Pool) start() {
	for i := 0; i < p.workers; i++ {
		p.wg.Add(1)
		go p.worker(i)
	}
}

func (p *Pool) worker(id int) {
	defer p.wg.Done()
	for t := range p.tasks {
		p.mu.Lock()
		p.active++
		p.mu.Unlock()

		p.logger.Info("worker starting task", "worker_id", id, "scope", t.ctx.Scope.String())
		err := t.fn(t.ctx)
		t.done <- err

		p.mu.Lock()
		p.active--
		p.mu.Unlock()

		p.budget.Release(t.ctx.Scope.Tenant)
	}
}

type PoolStatus struct {
	TotalWorkers  int `json:"total_workers"`
	ActiveWorkers int `json:"active_workers"`
}

func (p *Pool) Status() PoolStatus {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PoolStatus{
		TotalWorkers:  p.workers,
		ActiveWorkers: p.active,
	}
}

// Submit schedules a task to be executed by a worker.
func (p *Pool) Submit(ctx models.RuntimeContext, fn TaskFunc) chan error {
	done := make(chan error, 1)

	if !p.budget.Acquire(ctx.Scope.Tenant) {
		done <- context.Canceled // Budget exhausted
		return done
	}

	select {
	case <-ctx.Context.Done():
		p.budget.Release(ctx.Scope.Tenant)
		done <- ctx.Context.Err()
	case p.tasks <- taskWrapper{ctx: ctx, fn: fn, done: done}:
	}

	return done
}

func (p *Pool) Close() {
	p.once.Do(func() {
		close(p.tasks)
		p.wg.Wait()
	})
}
