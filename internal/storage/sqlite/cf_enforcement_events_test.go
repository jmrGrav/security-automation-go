package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/enforcementlog"
)

func TestEnforcementEventStore_AppendAndRecent(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewEnforcementEventStore(db)
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

	if err := store.Append(context.Background(), enforcementlog.Event{
		OccurredAt: now,
		Action:     enforcementlog.ActionBanApplied,
		IP:         "1.2.3.4",
		Reason:     "confidence_100",
		RuleID:     "rule-1",
		Success:    true,
		Duration:   120 * time.Millisecond,
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := store.Append(context.Background(), enforcementlog.Event{
		OccurredAt: now.Add(time.Minute),
		Action:     enforcementlog.ActionBanFailed,
		IP:         "5.6.7.8",
		Reason:     "burst",
		Success:    false,
		Error:      "cloudflare: 500",
	}); err != nil {
		t.Fatalf("Append: %v", err)
	}

	recent, err := store.Recent(context.Background(), 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("expected 2 events, got %d", len(recent))
	}
	if recent[0].IP != "5.6.7.8" {
		t.Errorf("expected newest first (5.6.7.8), got %s", recent[0].IP)
	}

	lastSuccess, ok, err := store.LastSuccess(context.Background())
	if err != nil || !ok {
		t.Fatalf("LastSuccess: err=%v ok=%v", err, ok)
	}
	if lastSuccess.IP != "1.2.3.4" {
		t.Errorf("expected last success IP=1.2.3.4, got %s", lastSuccess.IP)
	}

	lastFailure, ok, err := store.LastFailure(context.Background())
	if err != nil || !ok {
		t.Fatalf("LastFailure: err=%v ok=%v", err, ok)
	}
	if lastFailure.IP != "5.6.7.8" || lastFailure.Error == "" {
		t.Errorf("unexpected last failure: %+v", lastFailure)
	}
}

func TestEnforcementEventStore_NoEventsYet(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewEnforcementEventStore(db)

	recent, err := store.Recent(context.Background(), 10)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 0 {
		t.Errorf("expected no events, got %d", len(recent))
	}
	if _, ok, err := store.LastSuccess(context.Background()); err != nil || ok {
		t.Errorf("expected no last success: ok=%v err=%v", ok, err)
	}
	if _, ok, err := store.LastFailure(context.Background()); err != nil || ok {
		t.Errorf("expected no last failure: ok=%v err=%v", ok, err)
	}
}

func TestEnforcementEventStore_RespectsLimit(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewEnforcementEventStore(db)
	base := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 5; i++ {
		if err := store.Append(context.Background(), enforcementlog.Event{
			OccurredAt: base.Add(time.Duration(i) * time.Minute),
			Action:     enforcementlog.ActionBanApplied,
			IP:         "10.0.0.1",
			Success:    true,
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	recent, err := store.Recent(context.Background(), 2)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 2 {
		t.Fatalf("expected 2 events with limit=2, got %d", len(recent))
	}
}
