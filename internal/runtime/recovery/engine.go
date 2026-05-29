package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/jm/security-automation-go/internal/apperr"
)

type Engine struct {
	manager *Manager
	dbPath  string
}

func NewEngine(manager *Manager, dbPath string) *Engine {
	return &Engine{
		manager: manager,
		dbPath:  dbPath,
	}
}

func (e *Engine) Restore(ctx context.Context, snapshotID string) error {
	const op = "runtime.recovery.Engine.Restore"

	snapshots, err := e.manager.ListSnapshots()
	if err != nil {
		return err
	}

	var target *SnapshotMetadata
	for _, s := range snapshots {
		if s.ID == snapshotID {
			target = &s
			break
		}
	}

	if target == nil {
		return apperr.Newf(op, "snapshot %s not found", snapshotID)
	}

	// Verify checksum if available
	if target.Checksum != "" {
		if err := e.verifyChecksum(target.Path, target.Checksum); err != nil {
			return apperr.Wrap(op, err)
		}
	}

	// atomic restore
	tmpPath := e.dbPath + ".restore"
	if err := e.copyFile(target.Path, tmpPath); err != nil {
		return apperr.Wrap(op, err)
	}

	// Close connections to the main DB would be needed here in a real scenario
	// But we assume the caller handles that or we are in a recovery mode before DB init.

	if err := os.Rename(tmpPath, e.dbPath); err != nil {
		return apperr.Wrap(op, err)
	}

	// Also remove WAL and SHM files to ensure clean state
	_ = os.Remove(e.dbPath + "-wal")
	_ = os.Remove(e.dbPath + "-shm")

	return nil
}

func (e *Engine) verifyChecksum(path, expected string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return err
	}
	actual := hex.EncodeToString(hasher.Sum(nil))

	if actual != expected {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", expected, actual)
	}
	return nil
}

func (e *Engine) copyFile(src, dst string) error {
	source, err := os.Open(src)
	if err != nil {
		return err
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destination.Close()

	_, err = io.Copy(destination, source)
	return err
}
