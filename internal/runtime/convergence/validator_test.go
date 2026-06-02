package convergence

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/invariants"
	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestValidatorRejectsNilCurrentSnapshotWithoutPanic(t *testing.T) {
	t.Parallel()

	validator := NewValidator(invariants.New(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	target := &snapshot.Snapshot{}
	target.Integrity.SnapshotChecksum = "target"

	result, err := validator.Validate(context.Background(), target, nil)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if result.Converged {
		t.Fatal("nil current snapshot must not be considered converged")
	}
	if len(result.Violations) == 0 {
		t.Fatal("nil current snapshot should produce an invariant violation")
	}
}

func TestValidatorComparesSnapshotChecksums(t *testing.T) {
	t.Parallel()

	validator := NewValidator(invariants.New(), slog.New(slog.NewTextHandler(io.Discard, nil)))
	target := &snapshot.Snapshot{}
	target.Integrity.SnapshotChecksum = "target"
	current := &snapshot.Snapshot{}
	current.Integrity.SnapshotChecksum = "current"

	result, err := validator.Validate(context.Background(), target, current)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if result.Converged {
		t.Fatal("checksum mismatch must not be considered converged")
	}
}
