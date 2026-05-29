package sqlite

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"
)

func TestAbuseReportDedupStorePersistsAcrossRestart(t *testing.T) {
	dir := t.TempDir()

	db, err := New(dir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	store := NewAbuseReportDedupStore(db)
	ip := netip.MustParseAddr("8.8.8.8")
	reportedAt := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	if err := store.MarkReported(context.Background(), ip, reportedAt, "evidence-1"); err != nil {
		t.Fatalf("mark reported: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close db: %v", err)
	}

	reopened, err := New(dir)
	if err != nil {
		t.Fatalf("reopen db: %v", err)
	}
	defer reopened.Close()

	reopenedStore := NewAbuseReportDedupStore(reopened)
	got, found, err := reopenedStore.LastReportedAt(context.Background(), ip)
	if err != nil {
		t.Fatalf("last reported at: %v", err)
	}
	if !found || !got.Equal(reportedAt) {
		t.Fatalf("unexpected persisted value: found=%v got=%s want=%s", found, got, reportedAt)
	}
}

func TestCursorStorePersistsTime(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cursor")
	db, err := New(dir)
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewCursorStore(db)
	ts := time.Date(2026, 5, 27, 13, 0, 0, 0, time.UTC)
	if err := store.Save(context.Background(), "cloudflare_waf_since", ts); err != nil {
		t.Fatalf("save cursor: %v", err)
	}
	got, found, err := store.Load(context.Background(), "cloudflare_waf_since")
	if err != nil {
		t.Fatalf("load cursor: %v", err)
	}
	if !found || !got.Equal(ts) {
		t.Fatalf("unexpected cursor: found=%v got=%s want=%s", found, got, ts)
	}
}
