package journal

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/models"
)

func TestJSONLJournalPrunesByRetention(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	store := NewJSONLJournalWithPolicy(path, time.Hour, 10, 1, 1<<20)
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	events := []models.AuditEvent{
		{Timestamp: base.Add(-2 * time.Hour), RunID: "r1", Status: "completed"},
		{Timestamp: base.Add(-90 * time.Minute), RunID: "r2", Status: "completed"},
		{Timestamp: base.Add(-10 * time.Minute), RunID: "r3", Status: "completed"},
	}
	for _, ev := range events {
		if err := store.Append(ev); err != nil {
			t.Fatalf("append: %v", err)
		}
	}

	got, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 1 || got[0].RunID != "r3" {
		t.Fatalf("expected only recent event to remain, got %+v", got)
	}
}

func TestJSONLJournalCapsByCount(t *testing.T) {
	path := t.TempDir() + "/audit.jsonl"
	store := NewJSONLJournalWithPolicy(path, 24*time.Hour, 2, 1, 1<<20)
	base := time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)
	store.now = func() time.Time { return base }

	for i := 1; i <= 3; i++ {
		if err := store.Append(models.AuditEvent{
			Timestamp: base.Add(time.Duration(i) * time.Minute),
			RunID:     string(rune('0' + i)),
			Status:    "completed",
		}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	got, err := store.List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected journal to stay capped at 2 entries, got %d", len(got))
	}
	if got[0].RunID == "1" {
		t.Fatalf("expected oldest entry to be dropped, got %+v", got)
	}
}
