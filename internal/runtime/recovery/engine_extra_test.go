package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

func TestDetermineStrategy(t *testing.T) {
	t.Run("rollback", func(t *testing.T) {
		strategy, reason := DetermineStrategy(models.RuntimeState{ActiveRollbackID: "rb-1"})
		if strategy != StrategyResume {
			t.Fatalf("want resume, got %s", strategy)
		}
		if reason == "" {
			t.Fatal("expected rollback reason")
		}
	})
	t.Run("batch", func(t *testing.T) {
		strategy, reason := DetermineStrategy(models.RuntimeState{IncompleteBatchID: "batch-1"})
		if strategy != StrategyQuarantine {
			t.Fatalf("want quarantine, got %s", strategy)
		}
		if reason == "" {
			t.Fatal("expected batch reason")
		}
	})
	t.Run("clean", func(t *testing.T) {
		strategy, reason := DetermineStrategy(models.RuntimeState{})
		if strategy != StrategyResume || reason != "" {
			t.Fatalf("unexpected clean strategy: %s %q", strategy, reason)
		}
	})
}

func TestEngineRestoreCopiesSnapshotAndVerifiesChecksum(t *testing.T) {
	dir := t.TempDir()
	snapshotID := "20260529-150000"
	src := filepath.Join(dir, "snapshot-"+snapshotID+".db")
	dst := filepath.Join(dir, "runtime.db")
	data := []byte("snapshot-bytes")
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatal(err)
	}
	mgr := &Manager{dir: dir}
	eng := NewEngine(mgr, dst)
	if err := eng.Restore(context.Background(), snapshotID); err != nil {
		t.Fatalf("restore: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read restored file: %v", err)
	}
	if string(got) != string(data) {
		t.Fatalf("unexpected restore content: %q", got)
	}

	sum := sha256.Sum256(data)
	if err := eng.verifyChecksum(src, hex.EncodeToString(sum[:])); err != nil {
		t.Fatalf("verify checksum: %v", err)
	}
}

func TestEngineVerifyChecksum(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "snapshot.db")
	data := []byte("snapshot-bytes")
	if err := os.WriteFile(src, data, 0644); err != nil {
		t.Fatal(err)
	}
	eng := &Engine{}
	if err := eng.verifyChecksum(src, "bad"); err == nil {
		t.Fatal("expected checksum mismatch")
	}
}

func TestEngineRestoreMissingSnapshot(t *testing.T) {
	eng := NewEngine(&Manager{dir: t.TempDir()}, filepath.Join(t.TempDir(), "runtime.db"))
	if err := eng.Restore(context.Background(), "missing"); err == nil {
		t.Fatal("expected missing snapshot error")
	}
}

func TestEngineHelpers(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "input.db")
	data := []byte("abc")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	eng := &Engine{}
	if err := eng.verifyChecksum(path, "bad"); err == nil {
		t.Fatal("expected checksum failure")
	}
	if err := eng.copyFile(path, filepath.Join(dir, "copied.db")); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
}
