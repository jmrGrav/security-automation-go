package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDBHardeningHelpers(t *testing.T) {
	tmpDir := t.TempDir()
	db, err := New(tmpDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	if err := db.VerifySchema(context.Background()); err != nil {
		t.Fatalf("verify schema: %v", err)
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
}
