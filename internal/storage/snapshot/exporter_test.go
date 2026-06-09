package snapshot

import (
	"bytes"
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestExporter_Export_CreatesValidSnapshot(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	e := NewExporter(db)
	var buf bytes.Buffer
	if err := e.Export(context.Background(), &buf); err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if buf.Len() == 0 {
		t.Fatal("expected non-empty snapshot output")
	}
	// SQLite database files start with the magic header "SQLite format 3\000"
	if !bytes.HasPrefix(buf.Bytes(), []byte("SQLite format 3")) {
		t.Errorf("snapshot does not look like a SQLite file (first bytes: %q)", buf.Bytes()[:min(16, buf.Len())])
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
