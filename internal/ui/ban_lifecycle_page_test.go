package ui

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
)

type fakeBanLifecycleStore struct {
	entries []banlifecycle.Entry
	err     error
}

func (s *fakeBanLifecycleStore) Upsert(context.Context, banlifecycle.Entry) error { return nil }
func (s *fakeBanLifecycleStore) Get(context.Context, string) (banlifecycle.Entry, bool, error) {
	return banlifecycle.Entry{}, false, nil
}
func (s *fakeBanLifecycleStore) Active(context.Context) ([]banlifecycle.Entry, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.entries, nil
}
func (s *fakeBanLifecycleStore) Expired(context.Context, time.Time) ([]banlifecycle.Entry, error) {
	return nil, nil
}
func (s *fakeBanLifecycleStore) Recent(context.Context, int) ([]banlifecycle.Entry, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.entries, nil
}
func (s *fakeBanLifecycleStore) MarkStatus(context.Context, string, string, string) error {
	return nil
}
func (s *fakeBanLifecycleStore) RecidiveLevel(context.Context, string) (int, error) {
	return 0, nil
}

func TestBanLifecycleView_NotWired(t *testing.T) {
	s := &Server{}
	view := s.banLifecycleView(context.Background())
	if view.Wired {
		t.Fatal("expected Wired=false when no store is configured")
	}
}

func TestBanLifecycleView_RendersActiveEntries(t *testing.T) {
	now := time.Now().UTC()
	store := &fakeBanLifecycleStore{entries: []banlifecycle.Entry{
		{
			IP:            "203.0.113.5",
			Source:        "autoban_confidence_100",
			Reason:        "AbuseIPDB confidence 100 + local burst",
			Confidence:    100,
			CreatedAt:     now,
			ExpiresAt:     now.Add(time.Hour),
			Duration:      time.Hour,
			RuleID:        "rule-123",
			RecidiveLevel: 1,
			Status:        banlifecycle.StatusActive,
		},
	}}
	s := &Server{banLifecycleStore: store}
	view := s.banLifecycleView(context.Background())
	if !view.Wired {
		t.Fatal("expected Wired=true")
	}
	if len(view.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(view.Entries))
	}
	if view.Entries[0].IP != "203.0.113.5" || view.Entries[0].Confidence != 100 {
		t.Errorf("unexpected entry: %+v", view.Entries[0])
	}

	var buf strings.Builder
	if err := BanLifecyclePage(view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "203.0.113.5") {
		t.Error("expected rendered page to contain the banned IP")
	}
	if !strings.Contains(out, "rule-123") {
		t.Error("expected rendered page to contain the rule ID")
	}
}

func TestBanLifecycleView_PropagatesStoreError(t *testing.T) {
	store := &fakeBanLifecycleStore{err: errors.New("db unavailable")}
	s := &Server{banLifecycleStore: store}
	view := s.banLifecycleView(context.Background())
	if !view.Wired {
		t.Fatal("expected Wired=true even on error")
	}
	if view.Error == "" {
		t.Error("expected Error to be populated")
	}
}

func TestBanLifecyclePage_EmptyState(t *testing.T) {
	var buf strings.Builder
	if err := BanLifecyclePage(BanLifecycleView{Wired: true}).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	if !strings.Contains(buf.String(), "No managed Cloudflare ban lifecycle entries yet") {
		t.Error("expected empty-state message")
	}
}

func TestBanLifecycleView_RendersFullLifecycleHistory(t *testing.T) {
	now := time.Now().UTC()
	store := &fakeBanLifecycleStore{entries: []banlifecycle.Entry{
		{
			IP:            "198.51.100.9",
			Source:        "autoban_burst_malicious",
			Reason:        "expired and cleaned by cleanup worker",
			CreatedAt:     now.Add(-48 * time.Hour),
			ExpiresAt:     now.Add(-47 * time.Hour),
			Duration:      time.Hour,
			RuleID:        "rule-old",
			RecidiveLevel: 1,
			Status:        banlifecycle.StatusExpiredCleaned,
		},
		{
			IP:            "198.51.100.10",
			Source:        "autoban_confidence_100",
			Reason:        "auto-debanned after CrowdSec decision lifted",
			CreatedAt:     now.Add(-2 * time.Hour),
			ExpiresAt:     now.Add(-1 * time.Hour),
			Duration:      time.Hour,
			RuleID:        "rule-debanned",
			RecidiveLevel: 1,
			Status:        banlifecycle.StatusAutoDebanned,
		},
	}}
	s := &Server{banLifecycleStore: store}
	view := s.banLifecycleView(context.Background())
	if len(view.Entries) != 2 {
		t.Fatalf("expected 2 lifecycle entries, got %d", len(view.Entries))
	}

	var buf strings.Builder
	if err := BanLifecyclePage(view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "expired_cleaned") {
		t.Error("expected rendered page to show expired_cleaned status")
	}
	if !strings.Contains(out, "auto_debanned") {
		t.Error("expected rendered page to show auto_debanned status")
	}
}
