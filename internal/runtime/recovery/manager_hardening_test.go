package recovery

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/checkpoint"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
)

type hardeningCheckpointStore struct {
	checkpoints []events.Checkpoint
}

func (s *hardeningCheckpointStore) SaveCheckpoint(_ context.Context, checkpoint events.Checkpoint) error {
	s.checkpoints = append(s.checkpoints, checkpoint)
	return nil
}

func (s *hardeningCheckpointStore) LatestCheckpoint(_ context.Context, scopeID string, name string) (events.Checkpoint, error) {
	for i := len(s.checkpoints) - 1; i >= 0; i-- {
		cp := s.checkpoints[i]
		if cp.ScopeID == scopeID && cp.Name == name {
			return cp, nil
		}
	}
	return events.Checkpoint{}, events.ErrCheckpointNotFound
}

func (s *hardeningCheckpointStore) ListCheckpoints(_ context.Context, scopeID string, name string, limit int) ([]events.Checkpoint, error) {
	out := make([]events.Checkpoint, 0)
	for i := len(s.checkpoints) - 1; i >= 0; i-- {
		cp := s.checkpoints[i]
		if cp.ScopeID == scopeID && cp.Name == name {
			out = append(out, cp)
			if limit > 0 && len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *hardeningCheckpointStore) DeleteCheckpoint(_ context.Context, scopeID string, name string, sequence uint64) error {
	var kept []events.Checkpoint
	for _, cp := range s.checkpoints {
		if cp.ScopeID == scopeID && cp.Name == name && cp.Sequence == sequence {
			continue
		}
		kept = append(kept, cp)
	}
	s.checkpoints = kept
	return nil
}

type hardeningSequenceSource struct {
	last uint64
}

func (s hardeningSequenceSource) GetLastSequence(context.Context, string) (uint64, error) {
	return s.last, nil
}

func TestRecoveryModeAndReportString(t *testing.T) {
	t.Parallel()

	if got := recoveryMode(RecoveryOptions{TargetSequence: 42}); got != "sequence" {
		t.Fatalf("expected sequence mode, got %q", got)
	}
	if got := recoveryMode(RecoveryOptions{TargetTime: time.Date(2026, 6, 1, 15, 0, 0, 0, time.UTC)}); got != "time" {
		t.Fatalf("expected time mode, got %q", got)
	}
	if got := recoveryMode(RecoveryOptions{}); got != "latest" {
		t.Fatalf("expected latest mode, got %q", got)
	}

	report := RecoveryReport{
		ScopeID:            "scope-a",
		Mode:               "sequence",
		CheckpointSequence: 7,
		FinalSequence:      12,
		EventsApplied:      5,
		DivergenceDetected: true,
	}
	if got := report.String(); got == "" || got == "<nil>" {
		t.Fatal("expected stable string representation")
	}
}

func TestEventEnginePlanUsesCheckpointAndManifestChecksum(t *testing.T) {
	t.Parallel()

	store := &hardeningCheckpointStore{}
	seqSource := hardeningSequenceSource{last: 7}
	checkpoints := checkpoint.NewManager(store, seqSource, nil, 0)

	state := models.RuntimeState{}
	event := events.Event{
		ID:            11,
		Sequence:      7,
		Timestamp:     time.Date(2026, 6, 1, 16, 0, 0, 0, time.UTC),
		Category:      events.CategoryLifecycle,
		Type:          "runtime.state.saved",
		CorrelationID: "corr-1",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       json.RawMessage(`{"step":"checkpoint"}`),
	}
	saved, err := checkpoints.SaveRuntimeState(context.Background(), "scope-a", "manual", event, state)
	if err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}
	engine := &EventEngine{checkpoints: checkpoints}

	plan, manifest, err := engine.Plan(context.Background(), RecoveryOptions{
		ScopeID:        "scope-a",
		TargetSequence: 20,
		Reason:         "hardening",
	})
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	if !manifest.UsedCheckpoint || plan.ResumeFromSequence != saved.Sequence || plan.Mode != "sequence" {
		t.Fatalf("expected checkpoint-backed sequence plan, got plan=%+v manifest=%+v saved=%+v", plan, manifest, saved)
	}
	if manifest.Checksum != manifestChecksum(manifest) {
		t.Fatalf("manifest checksum must be canonical, got %+v", manifest)
	}
}

func TestManagerRotateKeepsNewestSnapshots(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	stamps := []string{"20260601-100000", "20260601-110000", "20260601-120000"}
	for _, stamp := range stamps {
		path := filepath.Join(dir, "snapshot-"+stamp+".db")
		if err := os.WriteFile(path, []byte(stamp), 0644); err != nil {
			t.Fatalf("write snapshot %s: %v", stamp, err)
		}
	}

	mgr := &Manager{dir: dir}
	if err := mgr.Rotate(context.Background(), 1); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	if _, err := os.Stat(filepath.Join(dir, "snapshot-20260601-120000.db")); err != nil {
		t.Fatalf("newest snapshot should remain: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "snapshot-20260601-110000.db")); !os.IsNotExist(err) {
		t.Fatalf("older snapshot should be removed, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "snapshot-20260601-100000.db")); !os.IsNotExist(err) {
		t.Fatalf("oldest snapshot should be removed, err=%v", err)
	}
}
