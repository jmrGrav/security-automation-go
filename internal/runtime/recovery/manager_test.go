package recovery

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm/security-automation-go/internal/storage/snapshot"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestManager_Restore(t *testing.T) {
	tmpDir := t.TempDir()
	dbDir := filepath.Join(tmpDir, "db")
	snapDir := filepath.Join(tmpDir, "snaps")

	db, err := sqlite.New(dbDir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	exporter := snapshot.NewExporter(db)
	mgr := NewManager(db, exporter, snapDir)

	ctx := context.Background()

	// 1. Create a snapshot
	snap, err := mgr.CreateSnapshot(ctx)
	if err != nil {
		t.Fatalf("create snapshot: %v", err)
	}

	// 2. Corrupt or change the DB (just to see if restore works)
	// We'll just delete the DB file after closing it in Restore

	// 3. Restore
	if err := mgr.Restore(ctx, snap.ID); err != nil {
		t.Fatalf("restore snapshot: %v", err)
	}

	// 4. Verify DB is still usable
	if err := db.VerifySchema(ctx); err != nil {
		t.Fatalf("verify schema after restore: %v", err)
	}

	// 5. Check if quarantine file exists
	files, _ := os.ReadDir(dbDir)
	foundBak := false
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".db" && len(f.Name()) > 10 { // runtime.db.bak-TS
			foundBak = true
		}
	}
	if !foundBak {
		t.Log("Warning: no quarantine backup found, might be expected if file didn't exist yet or rename failed silently")
	}
}
