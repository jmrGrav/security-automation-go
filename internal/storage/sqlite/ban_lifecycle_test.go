package sqlite

import (
	"context"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
)

func TestBanLifecycleStore_UpsertGetActive(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewBanLifecycleStore(db)
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	entry := banlifecycle.Entry{
		IP:            "1.2.3.4",
		Source:        "autoban_confidence_100",
		Reason:        "confidence_100",
		Confidence:    100,
		CreatedAt:     now,
		ExpiresAt:     now.Add(1 * time.Hour),
		Duration:      1 * time.Hour,
		RuleID:        "rule-1",
		EvidenceID:    "ev-1",
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	got, ok, err := store.Get(context.Background(), "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("Get: err=%v ok=%v", err, ok)
	}
	if got.RuleID != "rule-1" || got.RecidiveLevel != 1 || got.Status != banlifecycle.StatusActive {
		t.Fatalf("unexpected entry: %+v", got)
	}
	if !got.CreatedAt.Equal(now) || !got.ExpiresAt.Equal(now.Add(1*time.Hour)) {
		t.Fatalf("unexpected timestamps: %+v", got)
	}
	if got.Duration != 1*time.Hour {
		t.Fatalf("unexpected duration: %v", got.Duration)
	}

	active, err := store.Active(context.Background())
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(active) != 1 || active[0].IP != "1.2.3.4" {
		t.Fatalf("unexpected active entries: %+v", active)
	}
}

func TestBanLifecycleStore_UpsertReplacesActiveRow(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewBanLifecycleStore(db)
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	first := banlifecycle.Entry{
		IP: "5.5.5.5", CreatedAt: now, ExpiresAt: now.Add(1 * time.Hour),
		Duration: 1 * time.Hour, RuleID: "rule-a", RecidiveLevel: 1, Status: banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), first); err != nil {
		t.Fatalf("Upsert first: %v", err)
	}
	updated := first
	updated.RuleID = "rule-b"
	updated.Reason = "burst_malicious"
	if err := store.Upsert(context.Background(), updated); err != nil {
		t.Fatalf("Upsert updated: %v", err)
	}

	got, ok, err := store.Get(context.Background(), "5.5.5.5")
	if err != nil || !ok {
		t.Fatalf("Get: err=%v ok=%v", err, ok)
	}
	if got.RuleID != "rule-b" || got.Reason != "burst_malicious" {
		t.Fatalf("expected active row replaced in place, got %+v", got)
	}

	active, err := store.Active(context.Background())
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(active) != 1 {
		t.Fatalf("expected exactly one active row after re-upsert, got %d", len(active))
	}
}

func TestBanLifecycleStore_RecidiveLevelCountsPriorCompletedBans(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewBanLifecycleStore(db)
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

	level, err := store.RecidiveLevel(context.Background(), "9.9.9.9")
	if err != nil {
		t.Fatalf("RecidiveLevel (no history): %v", err)
	}
	if level != 0 {
		t.Fatalf("expected 0 prior bans, got %d", level)
	}

	ban1 := banlifecycle.Entry{IP: "9.9.9.9", CreatedAt: now, ExpiresAt: now.Add(time.Hour), RecidiveLevel: 1, Status: banlifecycle.StatusActive}
	if err := store.Upsert(context.Background(), ban1); err != nil {
		t.Fatalf("Upsert ban1: %v", err)
	}
	if err := store.MarkStatus(context.Background(), "9.9.9.9", banlifecycle.StatusExpiredCleaned, "expired"); err != nil {
		t.Fatalf("MarkStatus: %v", err)
	}

	level, err = store.RecidiveLevel(context.Background(), "9.9.9.9")
	if err != nil {
		t.Fatalf("RecidiveLevel (1 completed): %v", err)
	}
	if level != 1 {
		t.Fatalf("expected 1 prior completed ban, got %d", level)
	}

	ban2 := banlifecycle.Entry{IP: "9.9.9.9", CreatedAt: now.Add(2 * time.Hour), ExpiresAt: now.Add(26 * time.Hour), RecidiveLevel: 2, Status: banlifecycle.StatusActive}
	if err := store.Upsert(context.Background(), ban2); err != nil {
		t.Fatalf("Upsert ban2: %v", err)
	}

	active, err := store.Active(context.Background())
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	if len(active) != 1 || active[0].RecidiveLevel != 2 {
		t.Fatalf("expected single active level-2 entry, got %+v", active)
	}
}

func TestBanLifecycleStore_Expired(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewBanLifecycleStore(db)
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

	expiredEntry := banlifecycle.Entry{IP: "1.1.1.1", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour), RecidiveLevel: 1, Status: banlifecycle.StatusActive, RuleID: "r1"}
	notExpiredEntry := banlifecycle.Entry{IP: "2.2.2.2", CreatedAt: now.Add(-1 * time.Hour), ExpiresAt: now.Add(23 * time.Hour), RecidiveLevel: 2, Status: banlifecycle.StatusActive, RuleID: "r2"}
	if err := store.Upsert(context.Background(), expiredEntry); err != nil {
		t.Fatalf("Upsert expired: %v", err)
	}
	if err := store.Upsert(context.Background(), notExpiredEntry); err != nil {
		t.Fatalf("Upsert not expired: %v", err)
	}

	expired, err := store.Expired(context.Background(), now)
	if err != nil {
		t.Fatalf("Expired: %v", err)
	}
	if len(expired) != 1 || expired[0].IP != "1.1.1.1" {
		t.Fatalf("expected only 1.1.1.1 expired, got %+v", expired)
	}
}

func TestBanLifecycleStore_MarkStatusRemovesFromExpiredAndActive(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewBanLifecycleStore(db)
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	entry := banlifecycle.Entry{IP: "3.3.3.3", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour), RecidiveLevel: 1, Status: banlifecycle.StatusActive, RuleID: "r3"}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	if err := store.MarkStatus(context.Background(), "3.3.3.3", banlifecycle.StatusExpiredCleaned, "cleaned by worker"); err != nil {
		t.Fatalf("MarkStatus: %v", err)
	}

	// Re-run MarkStatus to verify idempotency (no error, no panic).
	if err := store.MarkStatus(context.Background(), "3.3.3.3", banlifecycle.StatusExpiredCleaned, "cleaned by worker again"); err != nil {
		t.Fatalf("MarkStatus second call: %v", err)
	}

	expired, err := store.Expired(context.Background(), now)
	if err != nil {
		t.Fatalf("Expired: %v", err)
	}
	for _, e := range expired {
		if e.IP == "3.3.3.3" {
			t.Fatalf("expected 3.3.3.3 to no longer be reported as expired after MarkStatus")
		}
	}
	active, err := store.Active(context.Background())
	if err != nil {
		t.Fatalf("Active: %v", err)
	}
	for _, e := range active {
		if e.IP == "3.3.3.3" {
			t.Fatalf("expected 3.3.3.3 to no longer be active after MarkStatus")
		}
	}

	got, ok, err := store.Get(context.Background(), "3.3.3.3")
	if err != nil || !ok {
		t.Fatalf("Get after MarkStatus: err=%v ok=%v", err, ok)
	}
	if got.Status != banlifecycle.StatusExpiredCleaned {
		t.Fatalf("expected status expired_cleaned, got %q", got.Status)
	}
}

func TestBanLifecycleStore_GetUnknownIPReturnsFalse(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewBanLifecycleStore(db)
	_, ok, err := store.Get(context.Background(), "0.0.0.0")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if ok {
		t.Fatalf("expected ok=false for unknown IP")
	}
}

func TestBanLifecycleStore_RecentReturnsFullHistoryAcrossStatuses(t *testing.T) {
	db, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("new db: %v", err)
	}
	defer db.Close()

	store := NewBanLifecycleStore(db)
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)

	entries := []banlifecycle.Entry{
		{IP: "10.0.0.1", CreatedAt: now.Add(-3 * time.Hour), ExpiresAt: now.Add(-2 * time.Hour), Status: banlifecycle.StatusExpiredCleaned},
		{IP: "10.0.0.2", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-1 * time.Hour), Status: banlifecycle.StatusAutoDebanned},
		{IP: "10.0.0.3", CreatedAt: now.Add(-1 * time.Hour), ExpiresAt: now, Status: banlifecycle.StatusManualOverride},
		{IP: "10.0.0.4", CreatedAt: now, ExpiresAt: now.Add(time.Hour), Status: banlifecycle.StatusActive},
	}
	for _, e := range entries {
		if err := store.Upsert(context.Background(), e); err != nil {
			t.Fatalf("Upsert(%s): %v", e.IP, err)
		}
	}

	recent, err := store.Recent(context.Background(), 100)
	if err != nil {
		t.Fatalf("Recent: %v", err)
	}
	if len(recent) != 4 {
		t.Fatalf("expected 4 entries across all statuses, got %d", len(recent))
	}
	// Newest first.
	if recent[0].IP != "10.0.0.4" || recent[0].Status != banlifecycle.StatusActive {
		t.Fatalf("expected newest entry first, got %+v", recent[0])
	}
	if recent[3].IP != "10.0.0.1" || recent[3].Status != banlifecycle.StatusExpiredCleaned {
		t.Fatalf("expected oldest entry last, got %+v", recent[3])
	}

	limited, err := store.Recent(context.Background(), 2)
	if err != nil {
		t.Fatalf("Recent with limit: %v", err)
	}
	if len(limited) != 2 {
		t.Fatalf("expected limit=2 to cap results, got %d", len(limited))
	}
}
