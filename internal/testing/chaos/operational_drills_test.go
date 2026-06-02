package chaos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/checkpoint"
	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

type replayDrillState struct {
	restored []events.Checkpoint
	applied  []uint64
}

func (r *replayDrillState) RestoreCheckpoint(_ context.Context, checkpoint events.Checkpoint) error {
	r.restored = append(r.restored, checkpoint)
	return nil
}

func (r *replayDrillState) ApplyEvent(_ context.Context, event events.Event) error {
	r.applied = append(r.applied, event.Sequence)
	return nil
}

func TestDrillEventReplayRestartDeterministic(t *testing.T) {
	dir := t.TempDir()
	db, err := sqlite.New(dir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := sqlite.NewEventRepository(db)
	ctx := context.Background()

	baseState := models.RuntimeState{
		Lifecycle: models.LifecycleState{Status: models.StatusPlanning, LastUpdatedAt: time.Now().UTC()},
	}
	ev1 := &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          events.TypeLifecycleTransition,
		CorrelationID: "corr-1",
		Actor:         "worker-a",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"from":"idle","to":"planning"}`),
	}
	if err := repo.Append(ctx, ev1); err != nil {
		t.Fatalf("append ev1: %v", err)
	}
	cp := events.Checkpoint{
		Name:          checkpoint.DefaultRuntimeCheckpointName,
		ScopeID:       "scope-a",
		Sequence:      ev1.Sequence,
		EventID:       ev1.ID,
		State:         []byte(`{"lifecycle":{"status":"planning"}}`),
		SchemaVersion: events.SchemaVersion,
		CreatedAt:     time.Now().UTC(),
	}
	cp.Checksum = checkpointChecksum(cp)
	if err := repo.SaveCheckpoint(ctx, cp); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}
	ev2 := &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          events.TypeLifecycleTransition,
		CorrelationID: "corr-1",
		Actor:         "worker-a",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"from":"planning","to":"executing"}`),
	}
	if err := repo.Append(ctx, ev2); err != nil {
		t.Fatalf("append ev2: %v", err)
	}

	_ = baseState
	first := &replayDrillState{}
	result, err := events.ReplayWithOptions(ctx, repo, "scope-a", first, events.ReplayOptions{CheckpointName: checkpoint.DefaultRuntimeCheckpointName})
	if err != nil {
		t.Fatalf("first replay: %v", err)
	}
	if !result.UsedCheckpoint || result.StartedAfterSequence != ev1.Sequence || result.FinalSequence != ev2.Sequence {
		t.Fatalf("unexpected first replay result: %+v", result)
	}
	if len(first.restored) != 1 || len(first.applied) != 1 || first.applied[0] != ev2.Sequence {
		t.Fatalf("unexpected first replay state: restored=%+v applied=%+v", first.restored, first.applied)
	}

	second := &replayDrillState{}
	result2, err := events.ReplayWithOptions(ctx, repo, "scope-a", second, events.ReplayOptions{CheckpointName: checkpoint.DefaultRuntimeCheckpointName})
	if err != nil {
		t.Fatalf("second replay: %v", err)
	}
	if result2.FinalSequence != result.FinalSequence || len(second.applied) != len(first.applied) || second.applied[0] != first.applied[0] {
		t.Fatalf("restart replay drift: first=%+v second=%+v", result, result2)
	}
}

func TestDrillOutboxReservationRetryDeterministic(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := sqlite.NewReportReservationStore(db)
	ctx := context.Background()
	base := time.Date(2026, 5, 31, 10, 0, 0, 0, time.UTC)
	first := reporting.ReportReservation{
		IP:             "8.8.8.8",
		Source:         "cloudflare_waf",
		IdempotencyKey: "idem-1",
		EvidenceID:     "ev-1",
		Status:         reporting.ReportStatusPending,
		ExpiresAt:      base.Add(-time.Minute),
	}
	if err := store.Reserve(ctx, first); err != nil {
		t.Fatalf("reserve first: %v", err)
	}
	if err := store.RecordAttempt(ctx, first.EvidenceID, reporting.ReportStatusFailed, "timeout", base.Add(time.Minute)); err != nil {
		t.Fatalf("record attempt: %v", err)
	}
	retryable, err := store.ListRetryable(ctx, base.Add(2*time.Minute), 10)
	if err != nil {
		t.Fatalf("list retryable: %v", err)
	}
	if len(retryable) != 1 || retryable[0].Reservation.EvidenceID != first.EvidenceID || retryable[0].LastError != "timeout" {
		t.Fatalf("unexpected retryable item: %+v", retryable)
	}
	second := first
	second.IdempotencyKey = "idem-2"
	second.EvidenceID = "ev-2"
	second.ExpiresAt = base.Add(time.Hour)
	if err := store.Reserve(ctx, second); err != nil {
		t.Fatalf("expected expired pending row to unlock retry: %v", err)
	}
}

func TestDrillLeaseSplitBrainRefusalDeterministic(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	stateStore := state.NewStateStore(t.TempDir())
	lease := models.Lease{ID: "lease-a", Owner: "worker-a", Action: "reconcile", EpochID: "epoch-1", FencingToken: 1, ExpiresAt: time.Now().Add(time.Hour)}
	if err := stateStore.Save(models.RuntimeState{ActiveLease: &lease}); err != nil {
		t.Fatalf("save state: %v", err)
	}

	leaseRepo := sqlite.NewLeaseRepository(db)
	if err := leaseRepo.AcquireLease(context.Background(), "scope-a", lease); err != nil {
		t.Fatalf("seed active lease: %v", err)
	}

	leaseMgr := coordination.NewLeaseManager(stateStore, time.Second).WithLeaseStore("scope-a", leaseRepo)
	_, _, acquireErr := leaseMgr.Acquire(context.Background(), "worker-b", "reconcile", "run-2")
	if acquireErr == nil {
		t.Fatal("expected second leader acquisition to be refused while lease is active")
	}
}

func checkpointChecksum(cp events.Checkpoint) string {
	payload, _ := json.Marshal(struct {
		Name          string          `json:"name"`
		ScopeID       string          `json:"scope_id"`
		Sequence      uint64          `json:"sequence"`
		EventID       int64           `json:"event_id"`
		State         json.RawMessage `json:"state"`
		Metadata      map[string]any  `json:"metadata,omitempty"`
		SchemaVersion int             `json:"schema_version"`
		CreatedAt     string          `json:"created_at"`
	}{
		Name:          cp.Name,
		ScopeID:       cp.ScopeID,
		Sequence:      cp.Sequence,
		EventID:       cp.EventID,
		State:         cp.State,
		Metadata:      cp.Metadata,
		SchemaVersion: cp.SchemaVersion,
		CreatedAt:     cp.CreatedAt.UTC().Format(time.RFC3339Nano),
	})
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
