package coalesce

import (
	"github.com/jm/security-automation-go/internal/execution"
)

// Coalescer optimizes mutation batches by removing redundant or canceling operations.
type Coalescer struct{}

func New() *Coalescer {
	return &Coalescer{}
}

// Coalesce simplifies a batch of operations.
func (c *Coalescer) Coalesce(ops []execution.MutationOperation) []execution.MutationOperation {
	if len(ops) <= 1 {
		return ops
	}

	// SIK -> effective operation
	lastSeen := make(map[string]execution.MutationOperation)

	for _, op := range ops {
		prev, exists := lastSeen[op.StableIdentityKey]
		if !exists {
			lastSeen[op.StableIdentityKey] = op
			continue
		}

		// Optimization logic:
		// 1. Create + Delete -> None (Canceling)
		// 2. Create + Update -> Create (with new payload)
		// 3. Update + Update -> Update (with latest payload)
		// 4. Update + Delete -> Delete
		// 5. Delete + Create -> Update (Transform)

		switch {
		case prev.Type == "create" && op.Type == "delete":
			delete(lastSeen, op.StableIdentityKey)
		case prev.Type == "create" && op.Type == "update":
			op.Type = "create"
			lastSeen[op.StableIdentityKey] = op
		case prev.Type == "delete" && op.Type == "create":
			op.Type = "update"
			lastSeen[op.StableIdentityKey] = op
		default:
			lastSeen[op.StableIdentityKey] = op
		}
	}

	// Note: In production, we must preserve the original ordering of different SIKs
	// (using an ordered map or re-sorting by original index).

	out := make([]execution.MutationOperation, 0, len(lastSeen))
	for _, op := range lastSeen {
		out = append(out, op)
	}
	return out
}
