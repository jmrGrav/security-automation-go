package pipeline

import (
	"context"
	"errors"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

type leaseBoundExecution struct {
	ctx       context.Context
	cancel    context.CancelCauseFunc
	heartbeat coordination.HeartbeatHandle
}

// newLeaseBoundExecution centralizes heartbeat-bound cancellation semantics so
// rollback and future forward write paths share the same lease-loss behavior.
func (o *Orchestrator) newLeaseBoundExecution(parent context.Context, lease models.Lease, interval time.Duration, ttl time.Duration, failures int) leaseBoundExecution {
	leaseCtx, cancel := context.WithCancelCause(parent)
	hb := o.leaseMgr.StartHeartbeat(leaseCtx, lease, coordination.HeartbeatConfig{
		Interval:         interval,
		TTL:              ttl,
		FailureThreshold: failures,
	})
	go func() {
		if lostErr, ok := <-hb.Lost(); ok && lostErr != nil {
			cancel(errors.New("lost lease: " + lostErr.Error()))
		}
	}()
	return leaseBoundExecution{
		ctx:       leaseCtx,
		cancel:    cancel,
		heartbeat: hb,
	}
}
