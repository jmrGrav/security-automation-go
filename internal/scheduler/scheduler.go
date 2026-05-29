package scheduler

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/logging"
)

type Task interface {
	Run(ctx context.Context) error
}

type IntervalRunner struct {
	Name     string
	Interval time.Duration
	Timeout  time.Duration

	mu      sync.Mutex
	running bool

	lastDurationNS int64
	failures       uint64
}

type Snapshot struct {
	Name         string
	Running      bool
	LastDuration time.Duration
	FailureCount uint64
	Timeout      time.Duration
	Interval     time.Duration
}

func (r *IntervalRunner) Run(ctx context.Context, task Task) error {
	const op = "scheduler.IntervalRunner.Run"

	if ctx == nil {
		return apperr.New(op, "context is required")
	}
	if task == nil {
		return apperr.New(op, "task is required")
	}
	if r.Interval <= 0 {
		return apperr.New(op, "interval must be positive")
	}

	if err := r.runOnce(ctx, task); err != nil && !errors.Is(err, context.Canceled) {
		return apperr.Wrap(op, err)
	}

	ticker := time.NewTicker(r.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if err := r.runOnce(ctx, task); err != nil && !errors.Is(err, context.Canceled) {
				return apperr.Wrap(op, err)
			}
		}
	}
}

func (r *IntervalRunner) Snapshot() Snapshot {
	r.mu.Lock()
	running := r.running
	r.mu.Unlock()

	return Snapshot{
		Name:         r.jobName(),
		Running:      running,
		LastDuration: time.Duration(atomic.LoadInt64(&r.lastDurationNS)),
		FailureCount: atomic.LoadUint64(&r.failures),
		Timeout:      r.Timeout,
		Interval:     r.Interval,
	}
}

func (r *IntervalRunner) runOnce(parent context.Context, task Task) error {
	const op = "scheduler.IntervalRunner.runOnce"

	r.mu.Lock()
	if r.running {
		r.mu.Unlock()
		atomic.AddUint64(&r.failures, 1)
		return apperr.New(op, "job overlap prevented")
	}
	r.running = true
	r.mu.Unlock()

	defer func() {
		r.mu.Lock()
		r.running = false
		r.mu.Unlock()
	}()

	ctx := logging.WithTraceLogger(parent, logging.FromContext(parent, slog.Default()))
	logger := logging.FromContext(ctx, slog.Default())
	start := time.Now()
	logger.InfoContext(ctx, "scheduler job started",
		"job", r.jobName(),
		"interval", r.Interval.String(),
		"timeout", r.Timeout.String(),
	)

	runCtx := ctx
	cancel := func() {}
	if r.Timeout > 0 {
		runCtx, cancel = context.WithTimeout(ctx, r.Timeout)
	}
	defer cancel()

	err := task.Run(runCtx)
	duration := time.Since(start)
	atomic.StoreInt64(&r.lastDurationNS, duration.Nanoseconds())

	if err != nil {
		atomic.AddUint64(&r.failures, 1)
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			logger.WarnContext(ctx, "scheduler job canceled",
				"job", r.jobName(),
				"duration", duration.String(),
				"failures", atomic.LoadUint64(&r.failures),
				"error", err.Error(),
			)
			return err
		}
		logger.ErrorContext(ctx, "scheduler job failed",
			"job", r.jobName(),
			"duration", duration.String(),
			"failures", atomic.LoadUint64(&r.failures),
			"error", err.Error(),
		)
		return apperr.Wrap(op, err)
	}

	logger.InfoContext(ctx, "scheduler job completed",
		"job", r.jobName(),
		"duration", duration.String(),
		"failures", atomic.LoadUint64(&r.failures),
	)
	return nil
}

func (r *IntervalRunner) jobName() string {
	if r.Name != "" {
		return r.Name
	}
	return "unnamed-job"
}
