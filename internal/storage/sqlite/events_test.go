package sqlite

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
)

func TestEventRepository(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "event-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()

	repo := NewEventRepository(db)
	ctx := context.Background()

	ev := &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "test_event",
		CorrelationID: "corr-1",
		Actor:         "test-actor",
		ScopeID:       "scope-1",
		Payload:       []byte(`{"foo":"bar"}`),
	}

	if err := repo.Append(ctx, ev); err != nil {
		t.Fatalf("failed to append event: %v", err)
	}

	if ev.ID == 0 {
		t.Error("expected event ID to be set")
	}

	last, err := repo.GetLastSequence(ctx, "scope-1")
	if err != nil {
		t.Fatalf("failed to get last sequence: %v", err)
	}
	if last != 1 {
		t.Errorf("expected last sequence 1, got %d", last)
	}

	list, err := repo.List(ctx, "scope-1", 0)
	if err != nil {
		t.Fatalf("failed to list events: %v", err)
	}
	if len(list) != 1 {
		t.Errorf("expected 1 event, got %d", len(list))
	}
	if list[0].Type != "test_event" {
		t.Errorf("expected type test_event, got %s", list[0].Type)
	}
}

func TestEventRepositoryAssignsPerScopeSequenceAndCheckpoint(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "event-checkpoint-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()

	repo := NewEventRepository(db)
	ctx := context.Background()

	ev1 := &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "started",
		CorrelationID: "corr-a",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":1}`),
	}
	ev2 := &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "continued",
		CorrelationID: "corr-a",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":2}`),
	}

	if err := repo.Append(ctx, ev1); err != nil {
		t.Fatalf("append ev1: %v", err)
	}
	if err := repo.Append(ctx, ev2); err != nil {
		t.Fatalf("append ev2: %v", err)
	}
	if ev1.Sequence != 1 || ev2.Sequence != 2 {
		t.Fatalf("expected sequences 1 and 2, got %d and %d", ev1.Sequence, ev2.Sequence)
	}

	checkpoint := events.Checkpoint{
		Name:          "runtime-state",
		ScopeID:       "scope-a",
		Sequence:      ev2.Sequence,
		EventID:       ev2.ID,
		Checksum:      "sha256:test",
		State:         json.RawMessage(`{"status":"converged"}`),
		Metadata:      map[string]any{"source": "test"},
		SchemaVersion: events.SchemaVersion,
		CreatedAt:     time.Now().UTC(),
	}
	if err := repo.SaveCheckpoint(ctx, checkpoint); err != nil {
		t.Fatalf("save checkpoint: %v", err)
	}

	got, err := repo.LatestCheckpoint(ctx, "scope-a", "runtime-state")
	if err != nil {
		t.Fatalf("latest checkpoint: %v", err)
	}
	if got.Sequence != ev2.Sequence {
		t.Fatalf("expected checkpoint sequence %d, got %d", ev2.Sequence, got.Sequence)
	}
	if string(got.State) != `{"status":"converged"}` {
		t.Fatalf("unexpected checkpoint state: %s", string(got.State))
	}
}

func TestEventRepositoryDeduplicatesEventUID(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()

	repo := NewEventRepository(db)
	ctx := context.Background()
	ev := &events.Event{
		UID:           "event-uid-1",
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "idempotent",
		CorrelationID: "corr",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":1}`),
	}
	if err := repo.Append(ctx, ev); err != nil {
		t.Fatalf("append first: %v", err)
	}
	firstID := ev.ID
	firstSeq := ev.Sequence

	dup := &events.Event{
		UID:           "event-uid-1",
		Timestamp:     ev.Timestamp,
		Category:      events.CategoryLifecycle,
		Type:          "idempotent",
		CorrelationID: "corr",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":1}`),
	}
	if err := repo.Append(ctx, dup); err != nil {
		t.Fatalf("append duplicate: %v", err)
	}
	if dup.ID != firstID || dup.Sequence != firstSeq {
		t.Fatalf("expected duplicate to reuse id/sequence %d/%d, got %d/%d", firstID, firstSeq, dup.ID, dup.Sequence)
	}
	list, err := repo.List(ctx, "scope-a", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected one persisted event, got %d", len(list))
	}
}

func TestEventRepositoryCommitAmbiguousExistingRowIsIdempotent(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()

	repo := NewEventRepository(db)
	repo.commit = func(tx *sql.Tx) error {
		if err := tx.Commit(); err != nil {
			return err
		}
		return errors.New("simulated lost commit acknowledgement")
	}
	ev := &events.Event{
		UID:           "event-uid-commit-exists",
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "commit_ambiguous",
		CorrelationID: "corr",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":1}`),
	}
	if err := repo.Append(context.Background(), ev); err != nil {
		t.Fatalf("expected idempotent success when committed row exists, got %v", err)
	}
	if ev.Sequence != 1 {
		t.Fatalf("expected committed sequence 1, got %d", ev.Sequence)
	}
}

func TestEventRepositoryCommitAmbiguousMissingRowReturnsTypedError(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()

	repo := NewEventRepository(db)
	repo.commit = func(tx *sql.Tx) error {
		_ = tx.Rollback()
		return errors.New("simulated ambiguous commit without durable row")
	}
	ev := &events.Event{
		UID:           "event-uid-commit-missing",
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "commit_ambiguous",
		CorrelationID: "corr",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":1}`),
	}
	err = repo.Append(context.Background(), ev)
	if !errors.Is(err, ErrCommitAmbiguous) {
		t.Fatalf("expected ErrCommitAmbiguous, got %v", err)
	}
	list, err := repo.List(context.Background(), "scope-a", 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected no durable rows after missing ambiguous commit, got %d", len(list))
	}
}

func TestEventRepositoryCheckpointListDeleteAndReadOnly(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "event-checkpoint-list-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()

	repo := NewEventRepository(db)
	ctx := context.Background()
	for _, seq := range []uint64{1, 2} {
		cp := events.Checkpoint{
			Name:          "runtime-state",
			ScopeID:       "scope-a",
			Sequence:      seq,
			EventID:       int64(seq),
			State:         json.RawMessage(`{}`),
			Metadata:      map[string]any{"trigger": "test"},
			SchemaVersion: events.SchemaVersion,
			CreatedAt:     time.Now().UTC(),
		}
		cp.Checksum = checkpointChecksum(cp)
		if err := repo.SaveCheckpoint(ctx, cp); err != nil {
			t.Fatalf("save checkpoint: %v", err)
		}
	}

	list, err := repo.ListCheckpoints(ctx, "scope-a", "runtime-state", 0)
	if err != nil || len(list) != 2 {
		t.Fatalf("list checkpoints: %v len=%d", err, len(list))
	}
	if err := repo.DeleteCheckpoint(ctx, "scope-a", "runtime-state", 1); err != nil {
		t.Fatalf("delete checkpoint: %v", err)
	}

	db.SetReadOnlyDegradedMode(true)
	cp := events.Checkpoint{
		Name:          "runtime-state",
		ScopeID:       "scope-a",
		Sequence:      3,
		EventID:       3,
		State:         json.RawMessage(`{}`),
		Metadata:      map[string]any{"trigger": "test"},
		SchemaVersion: events.SchemaVersion,
		CreatedAt:     time.Now().UTC(),
	}
	cp.Checksum = checkpointChecksum(cp)
	if err := repo.SaveCheckpoint(ctx, cp); err == nil {
		t.Fatal("expected read-only degraded mode error")
	}
}

func TestEventRepositoryConcurrentAppendSameScope(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()

	repo := NewEventRepository(db)
	ctx := context.Background()

	const total = 64
	var wg sync.WaitGroup
	errs := make(chan error, total)
	sequences := make(chan uint64, total)
	for i := 0; i < total; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ev := &events.Event{
				Timestamp:     time.Now().UTC(),
				Category:      events.CategoryLifecycle,
				Type:          "concurrent",
				CorrelationID: "corr",
				Actor:         "tester",
				ScopeID:       "scope-a",
				Payload:       []byte(`{"i":1}`),
			}
			if err := repo.Append(ctx, ev); err != nil {
				errs <- err
				return
			}
			sequences <- ev.Sequence
		}(i)
	}
	wg.Wait()
	close(errs)
	close(sequences)

	for err := range errs {
		if err != nil {
			t.Fatalf("append error: %v", err)
		}
	}

	got := make([]int, 0, total)
	for seq := range sequences {
		got = append(got, int(seq))
	}
	sort.Ints(got)
	if len(got) != total {
		t.Fatalf("expected %d sequences, got %d", total, len(got))
	}
	for i, seq := range got {
		if seq != i+1 {
			t.Fatalf("expected continuous sequences, got %v", got)
		}
	}
}

func TestEventRepositoryConcurrentAppendMultiScope(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("failed to create db: %v", err)
	}
	defer db.Close()

	repo := NewEventRepository(db)
	ctx := context.Background()

	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for _, scopeID := range []string{"scope-a", "scope-b"} {
		scopeID := scopeID
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- repo.Append(ctx, &events.Event{
					Timestamp:     time.Now().UTC(),
					Category:      events.CategoryLifecycle,
					Type:          "concurrent",
					CorrelationID: "corr",
					Actor:         "tester",
					ScopeID:       scopeID,
					Payload:       []byte(`{"ok":true}`),
				})
			}()
		}
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("append error: %v", err)
		}
	}

	for _, scopeID := range []string{"scope-a", "scope-b"} {
		last, err := repo.GetLastSequence(ctx, scopeID)
		if err != nil {
			t.Fatalf("last sequence for %s: %v", scopeID, err)
		}
		if last != 16 {
			t.Fatalf("expected 16 events for %s, got %d", scopeID, last)
		}
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
	sum := sha256Sum(payload)
	return sum
}

func sha256Sum(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}
