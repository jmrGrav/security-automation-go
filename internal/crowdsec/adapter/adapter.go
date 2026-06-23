// Package adapter implements CrowdSec mutation delegation (cscli command
// execution and a dry-run variant) behind the Executor contract below.
//
// Deferred boundary: no shipped binary currently constructs or calls an
// Executor — it is exercised only by this package's own tests. It is kept
// in the production tree intentionally as the delegation path for CrowdSec
// allowlist/ban mutations (see internal/app's sudoers cscli allowlist work),
// reserved for wiring into a live command path in a future change rather
// than deleted, since rebuilding cscli execution + dry-run safety semantics
// from scratch would be wasted work if/when that wiring happens.
package adapter

import (
	"context"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// Executor defines the contract for applying CrowdSec actions.
type Executor interface {
	Execute(ctx context.Context, batch models.Batch) (models.BatchResult, error)
}
