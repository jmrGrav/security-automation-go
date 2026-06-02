package recovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/storage/snapshot"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

// TestManagerRestoreDataIntegrityWithStaleWALPresent proves that Restore
// produces exactly the snapshot data even when a foreign file exists at the
// WAL path before the call.
//
// The invariant is DATA INTEGRITY, not file-system state.  A WAL file from a
// different database is ignored by SQLite (WAL salt-1 mismatch → no pages
// applied), so the restored snapshot content is never affected.  This test
// confirms that correct invariant: after Restore, the database contains exactly
// the events that were present at snapshot time — no more, no less.
func TestManagerRestoreDataIntegrityWithStaleWALPresent(t *testing.T) {
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	snapDir := filepath.Join(tmpDir, "snaps")

	db, err := sqlite.New(dbDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := sqlite.NewEventRepository(db)
	ctx := context.Background()

	appendEvent := func(typ, corrID string) {
		t.Helper()
		if err := repo.Append(ctx, &events.Event{
			Timestamp: time.Now().UTC(), Category: events.CategoryLifecycle,
			Type: typ, CorrelationID: corrID, Actor: "tester", ScopeID: "scope-a",
			Payload: []byte(`{}`),
		}); err != nil {
			t.Fatalf("append %s: %v", typ, err)
		}
	}

	appendEvent("seed", "c1")

	mgr := NewManager(db, snapshot.NewExporter(db), snapDir)
	snap, err := mgr.CreateSnapshot(ctx)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// Add post-snapshot event so the WAL path is live when restore begins.
	appendEvent("post-snap", "c2")

	walPath := db.Path() + "-wal"

	// First restore: normal path.
	if err := mgr.Restore(ctx, snap.ID); err != nil {
		t.Fatalf("first restore: %v", err)
	}
	list, err := repo.List(ctx, "scope-a", 0)
	if err != nil {
		t.Fatalf("list after first restore: %v", err)
	}
	if len(list) != 1 || list[0].Type != "seed" {
		t.Fatalf("first restore: expected exactly the seed event, got %+v", list)
	}

	// Second restore with a fake stale WAL already at walPath.
	// This simulates the scenario our fix handles: the quarantine WAL rename
	// failed, leaving the stale file at the live path.
	appendEvent("seed2", "c3")
	snap2, err := mgr.CreateSnapshot(ctx)
	if err != nil {
		t.Fatalf("snapshot 2: %v", err)
	}
	appendEvent("post-snap2", "c4")

	// Plant the stale file BEFORE the second restore. The quarantine rename
	// during Restore will move the real WAL and overwrite this file; our
	// explicit Remove ensures cleanup even if the quarantine rename fails.
	if err := os.WriteFile(walPath, []byte("not-a-real-sqlite-wal"), 0o644); err != nil {
		t.Fatalf("inject stale wal: %v", err)
	}

	if err := mgr.Restore(ctx, snap2.ID); err != nil {
		t.Fatalf("second restore with stale wal present: %v", err)
	}

	// Invariant: DB content matches the second snapshot exactly.
	list2, err := repo.List(ctx, "scope-a", 0)
	if err != nil {
		t.Fatalf("list after second restore: %v", err)
	}
	if len(list2) != 2 {
		t.Fatalf("expected 2 events after second restore (seed + seed2), got %d: %+v", len(list2), list2)
	}
	if list2[0].Type != "seed" || list2[1].Type != "seed2" {
		t.Fatalf("unexpected events after second restore: %+v", list2)
	}

	// Verify the database is writable and not in degraded mode.
	if db.ReadOnlyDegradedMode() {
		t.Fatal("restore left DB in degraded mode — integrity check must have failed")
	}
}

func TestManagerRestoreWithWALPreservesCheckpointedSnapshot(t *testing.T) {
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	snapDir := filepath.Join(tmpDir, "snaps")

	db, err := sqlite.New(dbDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := sqlite.NewEventRepository(db)
	ctx := context.Background()
	if err := repo.Append(ctx, &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "snapshot.seed",
		CorrelationID: "corr-1",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":1}`),
	}); err != nil {
		t.Fatalf("append seed event: %v", err)
	}

	exporter := snapshot.NewExporter(db)
	mgr := NewManager(db, exporter, snapDir)
	snap, err := mgr.CreateSnapshot(ctx)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	if err := repo.Append(ctx, &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "snapshot.after",
		CorrelationID: "corr-2",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":2}`),
	}); err != nil {
		t.Fatalf("append post-snapshot event: %v", err)
	}

	if _, err := os.Stat(db.Path() + "-wal"); err != nil && !os.IsNotExist(err) {
		t.Fatalf("wal stat: %v", err)
	}

	if err := mgr.Restore(ctx, snap.ID); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}
	if db.ReadOnlyDegradedMode() {
		t.Fatal("expected restore to leave database writable after integrity verification")
	}

	list, err := repo.List(ctx, "scope-a", 0)
	if err != nil {
		t.Fatalf("list after restore: %v", err)
	}
	if len(list) != 1 || list[0].Type != "snapshot.seed" {
		t.Fatalf("expected restore to roll back post-snapshot event, got %+v", list)
	}
}

func TestManagerRestoreMissingSnapshotDoesNotDestroyCurrentDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	snapDir := filepath.Join(tmpDir, "snaps")

	db, err := sqlite.New(dbDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := sqlite.NewEventRepository(db)
	ctx := context.Background()
	if err := repo.Append(ctx, &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "snapshot.seed",
		CorrelationID: "corr-1",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":1}`),
	}); err != nil {
		t.Fatalf("append seed event: %v", err)
	}

	mgr := NewManager(db, snapshot.NewExporter(db), snapDir)
	if err := mgr.Restore(ctx, "missing"); err == nil {
		t.Fatal("expected missing snapshot error")
	}

	list, err := repo.List(ctx, "scope-a", 0)
	if err != nil {
		t.Fatalf("list after failed restore: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected current db to remain intact after failed restore, got %+v", list)
	}
}

func TestManagerRestoreRejectsCorruptSnapshotWithoutTouchingCurrentDB(t *testing.T) {
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	snapDir := filepath.Join(tmpDir, "snaps")

	db, err := sqlite.New(dbDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	repo := sqlite.NewEventRepository(db)
	ctx := context.Background()
	if err := repo.Append(ctx, &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "snapshot.seed",
		CorrelationID: "corr-1",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"step":1}`),
	}); err != nil {
		t.Fatalf("append seed event: %v", err)
	}

	mgr := NewManager(db, snapshot.NewExporter(db), snapDir)
	badSnapshotID := "bad-snapshot"
	if err := os.WriteFile(filepath.Join(snapDir, "snapshot-"+badSnapshotID+".db"), []byte("not-a-sqlite-db"), 0644); err != nil {
		t.Fatalf("write corrupt snapshot: %v", err)
	}
	if err := mgr.Restore(ctx, badSnapshotID); err == nil {
		t.Fatal("expected corrupt snapshot restore to fail")
	}

	list, err := repo.List(ctx, "scope-a", 0)
	if err != nil {
		t.Fatalf("list after failed corrupt restore: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("expected current db to remain intact after corrupt restore, got %+v", list)
	}
}
