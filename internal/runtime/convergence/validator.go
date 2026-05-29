package convergence

import (
	"context"
	"log/slog"

	"github.com/jm/security-automation-go/internal/runtime/invariants"
	"github.com/jm/security-automation-go/internal/snapshot"
)

type ValidationResult struct {
	Converged  bool
	Violations []invariants.Violation
	Snapshot   *snapshot.Snapshot
}

// Validator ensures state converges after execution.
type Validator struct {
	invariantEng *invariants.Engine
	logger       *slog.Logger
}

func NewValidator(eng *invariants.Engine, logger *slog.Logger) *Validator {
	return &Validator{
		invariantEng: eng,
		logger:       logger,
	}
}

// Validate compares the current remote state against the target snapshot.
func (v *Validator) Validate(ctx context.Context, target *snapshot.Snapshot, current *snapshot.Snapshot) (ValidationResult, error) {
	const op = "runtime.convergence.Validate"

	res := ValidationResult{
		Converged: true,
		Snapshot:  current,
	}

	// 1. Invariant checking
	violations := v.invariantEng.Validate(ctx, current)
	if len(violations) > 0 {
		res.Converged = false
		res.Violations = violations
		v.logger.Warn("invariant violations detected during convergence validation", "count", len(violations))
	}

	// 2. Canonical hash comparison
	if target != nil && current.Integrity.SnapshotChecksum != target.Integrity.SnapshotChecksum {
		res.Converged = false
		v.logger.Warn("state not converged",
			"current_checksum", current.Integrity.SnapshotChecksum,
			"target_checksum", target.Integrity.SnapshotChecksum)
	}

	return res, nil
}
