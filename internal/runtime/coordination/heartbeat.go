package coordination

import (
	"context"
	"sync"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

type HeartbeatConfig struct {
	Interval         time.Duration
	TTL              time.Duration
	FailureThreshold int
	OnLost           func(error)
}

type HeartbeatHandle struct {
	done <-chan struct{}
	lost <-chan error
	stop context.CancelFunc
}

func (h HeartbeatHandle) Stop() {
	if h.stop != nil {
		h.stop()
	}
}

func (h HeartbeatHandle) Done() <-chan struct{} {
	return h.done
}

func (h HeartbeatHandle) Lost() <-chan error {
	return h.lost
}

func (m *LeaseManager) StartHeartbeat(ctx context.Context, lease models.Lease, cfg HeartbeatConfig) HeartbeatHandle {
	childCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	lost := make(chan error, 1)
	if cfg.Interval <= 0 {
		cfg.Interval = m.expiry / 2
	}
	if cfg.Interval <= 0 {
		cfg.Interval = time.Second
	}
	if cfg.TTL <= 0 {
		cfg.TTL = m.expiry
	}
	if cfg.TTL <= 0 {
		cfg.TTL = cfg.Interval * 2
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}

	var once sync.Once
	reportLost := func(err error) {
		once.Do(func() {
			if cfg.OnLost != nil {
				cfg.OnLost(err)
			}
			lost <- err
			cancel()
		})
	}

	go func() {
		defer close(done)
		defer close(lost)

		ticker := time.NewTicker(cfg.Interval)
		defer ticker.Stop()

		var failures int
		for {
			select {
			case <-childCtx.Done():
				return
			case <-ticker.C:
				renewCtx, renewCancel := context.WithTimeout(childCtx, minDuration(cfg.Interval, cfg.TTL)/2)
				if deadline, ok := childCtx.Deadline(); ok && time.Until(deadline) < minDuration(cfg.Interval, cfg.TTL)/2 {
					renewCancel()
					renewCtx, renewCancel = context.WithDeadline(childCtx, deadline)
				}
				err := m.Renew(renewCtx, lease.ID, cfg.TTL)
				renewCancel()
				if err != nil {
					failures++
					if failures >= cfg.FailureThreshold {
						reportLost(err)
						return
					}
					continue
				}
				failures = 0
			}
		}
	}()

	return HeartbeatHandle{done: done, lost: lost, stop: cancel}
}

func minDuration(left time.Duration, right time.Duration) time.Duration {
	if left <= 0 {
		return right
	}
	if right <= 0 || left < right {
		return left
	}
	return right
}
