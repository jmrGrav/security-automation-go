package scheduler

import (
	"context"
	"log/slog"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/lock"
)

type Task interface {
	Run(ctx context.Context) error
}

// DaemonScheduler coordinates the long-running reconciliation loop.
type DaemonScheduler struct {
	logger   *slog.Logger
	lock     *lock.FileLock
	interval time.Duration
}

func New(logger *slog.Logger, lock *lock.FileLock, interval time.Duration) *DaemonScheduler {
	if interval < 10*time.Second {
		interval = 10 * time.Second // Safety minimum
	}
	return &DaemonScheduler{
		logger:   logger,
		lock:     lock,
		interval: interval,
	}
}

func (s *DaemonScheduler) Start(ctx context.Context, task Task) error {
	s.logger.Info("starting daemon loop", "interval", s.interval)

	// 1. Acquire single-flight lock
	acquired, err := s.lock.Acquire()
	if err != nil {
		return err
	}
	if !acquired {
		s.logger.Error("failed to acquire daemon lock: another instance is already running")
		return nil
	}
	defer s.lock.Release()

	// 2. Loop until context cancellation
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run once immediately
	s.runOnce(ctx, task)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("stopping daemon loop")
			return ctx.Err()
		case <-ticker.C:
			s.runOnce(ctx, task)
		}
	}
}

func (s *DaemonScheduler) runOnce(ctx context.Context, task Task) {
	s.logger.Debug("starting reconciliation run")
	start := time.Now()

	err := task.Run(ctx)

	duration := time.Since(start)
	if err != nil {
		s.logger.Error("reconciliation run failed", "error", err, "duration", duration)
	} else {
		s.logger.Info("reconciliation run completed", "duration", duration)
	}
}
