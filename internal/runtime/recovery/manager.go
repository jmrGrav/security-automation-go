package recovery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/storage/snapshot"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

type SnapshotMetadata struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"ts"`
	Checksum  string    `json:"checksum"`
	Path      string    `json:"path"`
}

type Manager struct {
	db       *sqlite.DB
	exporter *snapshot.Exporter
	dir      string
}

func NewManager(db *sqlite.DB, exporter *snapshot.Exporter, dir string) *Manager {
	_ = os.MkdirAll(dir, 0755)
	return &Manager{
		db:       db,
		exporter: exporter,
		dir:      dir,
	}
}

func (m *Manager) Restore(ctx context.Context, snapshotID string) error {
	const op = "runtime.recovery.Manager.Restore"

	path := filepath.Join(m.dir, fmt.Sprintf("snapshot-%s.db", snapshotID))
	if _, err := os.Stat(path); err != nil {
		return apperr.Wrapf(op, err, "snapshot not found: %s", snapshotID)
	}

	// 1. Close active DB
	if err := m.db.Close(); err != nil {
		return apperr.Wrap(op, err)
	}

	// 2. Quarantine current (if exists)
	curPath := m.db.Path()
	if _, err := os.Stat(curPath); err == nil {
		quarantinePath := curPath + ".bak-" + time.Now().Format("20060102-150405")
		if err := os.Rename(curPath, quarantinePath); err != nil {
			return apperr.Wrap(op, err)
		}
		// Also move WAL/SHM if they exist
		_ = os.Rename(curPath+"-wal", quarantinePath+"-wal")
		_ = os.Rename(curPath+"-shm", quarantinePath+"-shm")
	}

	// 3. Copy snapshot to active path
	if err := copyFile(path, curPath); err != nil {
		return apperr.Wrap(op, err)
	}

	// 4. Reopen and verify
	return m.db.Reopen(ctx)
}

func copyFile(src, dst string) error {
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

func (m *Manager) CreateSnapshot(ctx context.Context) (*SnapshotMetadata, error) {
	const op = "runtime.recovery.Manager.CreateSnapshot"

	ts := time.Now().UTC()
	id := ts.Format("20060102-150405")
	path := filepath.Join(m.dir, fmt.Sprintf("snapshot-%s.db", id))

	f, err := os.Create(path)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}
	defer f.Close()

	if err := m.exporter.Export(ctx, f); err != nil {
		_ = os.Remove(path)
		return nil, apperr.Wrap(op, err)
	}

	// Calculate checksum
	if _, err := f.Seek(0, 0); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		return nil, apperr.Wrap(op, err)
	}
	checksum := hex.EncodeToString(hasher.Sum(nil))

	return &SnapshotMetadata{
		ID:        id,
		Timestamp: ts,
		Checksum:  checksum,
		Path:      path,
	}, nil
}

func (m *Manager) ListSnapshots() ([]SnapshotMetadata, error) {
	const op = "runtime.recovery.Manager.ListSnapshots"

	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return nil, apperr.Wrap(op, err)
	}

	var snapshots []SnapshotMetadata
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), "snapshot-") || !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}

		if _, err := entry.Info(); err != nil {
			continue
		}

		id := strings.TrimSuffix(strings.TrimPrefix(entry.Name(), "snapshot-"), ".db")
		ts, err := time.Parse("20060102-150405", id)
		if err != nil {
			continue
		}

		snapshots = append(snapshots, SnapshotMetadata{
			ID:        id,
			Timestamp: ts,
			Path:      filepath.Join(m.dir, entry.Name()),
		})
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].Timestamp.After(snapshots[j].Timestamp)
	})

	return snapshots, nil
}

func (m *Manager) Rotate(ctx context.Context, keep int) error {
	snapshots, err := m.ListSnapshots()
	if err != nil {
		return err
	}

	if len(snapshots) <= keep {
		return nil
	}

	for _, s := range snapshots[keep:] {
		_ = os.Remove(s.Path)
	}

	return nil
}
