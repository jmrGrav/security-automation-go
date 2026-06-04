package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
)

func TestDBHardeningHelpers(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}

	if err := db.VerifySchema(context.Background()); err != nil {
		t.Fatalf("verify schema: %v", err)
	}
	if db.Path() == "" {
		t.Fatal("expected database path")
	}
	if err := db.WALCheckpoint(context.Background(), "TRUNCATE"); err != nil {
		t.Fatalf("wal checkpoint: %v", err)
	}

	backupDir := filepath.Join(tmpDir, "backups")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		t.Fatalf("mkdir backups: %v", err)
	}
	snapshotPath := filepath.Join(backupDir, "runtime-snapshot.db")
	if err := db.ExportHotSnapshot(context.Background(), snapshotPath); err != nil {
		t.Fatalf("export hot snapshot: %v", err)
	}
	if _, err := os.Stat(snapshotPath); err != nil {
		t.Fatalf("expected snapshot file: %v", err)
	}

	db.SetReadOnlyDegradedMode(true)
	if !db.ReadOnlyDegradedMode() {
		t.Fatal("expected read-only degraded mode")
	}

	if err := db.Reopen(context.Background()); err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	if err := db.VerifySchema(context.Background()); err != nil {
		t.Fatalf("verify schema after reopen: %v", err)
	}

	backup1 := filepath.Join(backupDir, "b1.db")
	backup2 := filepath.Join(backupDir, "b2.db")
	if err := os.WriteFile(backup1, []byte("1"), 0644); err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	if err := os.WriteFile(backup2, []byte("2"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := db.RotateBackups(backupDir, 1); err != nil {
		t.Fatalf("rotate backups: %v", err)
	}
	if _, err := os.Stat(backup2); err != nil {
		t.Fatalf("expected newest backup to remain: %v", err)
	}
	if _, err := os.Stat(backup1); !os.IsNotExist(err) {
		t.Fatalf("expected oldest backup removed, got err=%v", err)
	}

	quarantineDir := filepath.Join(tmpDir, "quarantine")
	if path, err := db.QuarantineCorruption(context.Background(), quarantineDir); err != nil {
		t.Fatalf("quarantine corruption on healthy db: %v", err)
	} else if path != "" {
		t.Fatalf("expected no quarantine path for healthy db, got %q", path)
	}

	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}
}

func TestDBQuarantineCorruptionCopiesFilesOnIntegrityFailure(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	db.integrityCheck = func(context.Context) error {
		return context.Canceled
	}

	quarantineDir := filepath.Join(tmpDir, "quarantine")
	path, err := db.QuarantineCorruption(context.Background(), quarantineDir)
	if err != nil {
		t.Fatalf("quarantine corruption: %v", err)
	}
	if path == "" {
		t.Fatal("expected quarantine path on integrity failure")
	}
	if !db.ReadOnlyDegradedMode() {
		t.Fatal("expected degraded mode after corruption quarantine")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected quarantine artifact: %v", err)
	}
	if _, err := os.Stat(path + "-wal"); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected wal stat error: %v", err)
	}
	if _, err := os.Stat(path + "-shm"); err != nil && !os.IsNotExist(err) {
		t.Fatalf("unexpected shm stat error: %v", err)
	}
	repo := NewEventRepository(db)
	if err := repo.Append(context.Background(), &events.Event{
		Timestamp:     time.Now().UTC(),
		Category:      events.CategoryLifecycle,
		Type:          "write.after.quarantine",
		CorrelationID: "corr",
		Actor:         "tester",
		ScopeID:       "scope-a",
		Payload:       []byte(`{"blocked":true}`),
	}); err == nil {
		t.Fatal("expected writes to fail closed in degraded mode")
	}
}

func TestWALCheckpoint_RejectsUnknownMode(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	cases := []string{"DROP", "'; DROP TABLE events; --", "INVALIDMODE", "passive; DROP TABLE events"}
	for _, mode := range cases {
		if err := db.WALCheckpoint(context.Background(), mode); err == nil {
			t.Errorf("WALCheckpoint(%q) should have been rejected", mode)
		}
	}
}

func TestWALCheckpoint_AcceptsValidModes(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	for _, mode := range []string{"PASSIVE", "FULL", "RESTART", "TRUNCATE", ""} {
		if err := db.WALCheckpoint(context.Background(), mode); err != nil {
			t.Errorf("WALCheckpoint(%q) should have been accepted: %v", mode, err)
		}
	}
}

func TestExportHotSnapshot_RejectsInvalidPaths(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	cases := []string{
		"",
		"relative/path/db",
		"/tmp/../etc/passwd",
	}
	for _, p := range cases {
		if err := db.ExportHotSnapshot(context.Background(), p); err == nil {
			t.Errorf("ExportHotSnapshot(%q) should have been rejected", p)
		}
	}
}
