package snapshot

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

// Exporter handles transactional exports of the database state.
type Exporter struct {
	db *sqlite.DB
}

func NewExporter(db *sqlite.DB) *Exporter {
	return &Exporter{db: db}
}

// Export creates a consistent backup of the database to the target writer.
func (e *Exporter) Export(ctx context.Context, w io.Writer) error {
	const op = "storage.snapshot.Export"

	// SQLite-specific transactional backup using VACUUM INTO (Atomic Snapshot)
	tmpPath := fmt.Sprintf("/tmp/backup-%d.db", time.Now().UnixNano())
	defer os.Remove(tmpPath)

	if _, err := e.db.Conn().ExecContext(ctx, "VACUUM INTO ?", tmpPath); err != nil {
		return apperr.Wrap(op, err)
	}

	f, err := os.Open(tmpPath)
	if err != nil {
		return apperr.Wrap(op, err)
	}
	defer f.Close()

	_, err = io.Copy(w, f)
	return apperr.Wrap(op, err)
}
