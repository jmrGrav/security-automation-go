package scheduler

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type taskFunc func(context.Context) error

func (f taskFunc) Run(ctx context.Context) error {
	return f(ctx)
}

func TestIntervalRunnerRunsTaskImmediately(t *testing.T) {
	var calls atomic.Int32

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runner := IntervalRunner{Name: "immediate", Interval: 10 * time.Millisecond}
	err := runner.Run(ctx, taskFunc(func(context.Context) error {
		if calls.Add(1) == 1 {
			cancel()
		}
		return nil
	}))

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("unexpected call count: %d", calls.Load())
	}
}

func TestIntervalRunnerRejectsInvalidInterval(t *testing.T) {
	runner := IntervalRunner{}
	err := runner.Run(context.Background(), taskFunc(func(context.Context) error { return nil }))
	if err == nil {
		t.Fatal("expected error for invalid interval")
	}
}

func TestIntervalRunnerAppliesTimeout(t *testing.T) {
	runner := IntervalRunner{Name: "timeout", Interval: time.Hour, Timeout: 10 * time.Millisecond}
	err := runner.Run(context.Background(), taskFunc(func(ctx context.Context) error {
		<-ctx.Done()
		return ctx.Err()
	}))

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected deadline exceeded, got %v", err)
	}
}

func TestIntervalRunnerTracksFailuresAndDuration(t *testing.T) {
	runner := IntervalRunner{Name: "metrics", Interval: time.Hour}
	err := runner.Run(context.Background(), taskFunc(func(context.Context) error {
		return errors.New("boom")
	}))
	if err == nil {
		t.Fatal("expected job error")
	}

	snap := runner.Snapshot()
	if snap.FailureCount != 1 {
		t.Fatalf("unexpected failure count: %d", snap.FailureCount)
	}
	if snap.LastDuration <= 0 {
		t.Fatalf("expected positive duration, got %s", snap.LastDuration)
	}
}

func TestIntervalRunnerPreventsOverlap(t *testing.T) {
	runner := &IntervalRunner{Name: "overlap", Interval: time.Hour}
	ctx := context.Background()

	started := make(chan struct{})
	release := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_ = runner.runOnce(ctx, taskFunc(func(context.Context) error {
			close(started)
			<-release
			return nil
		}))
	}()

	<-started
	err := runner.runOnce(ctx, taskFunc(func(context.Context) error { return nil }))
	close(release)
	wg.Wait()

	if err == nil {
		t.Fatal("expected overlap prevention error")
	}
}
