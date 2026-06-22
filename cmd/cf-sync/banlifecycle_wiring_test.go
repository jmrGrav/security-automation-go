package main

import (
	"context"
	"testing"
	"time"

	cfpkg "github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/services/autoban"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// fakeEnforcementClient is a minimal cfpkg.EnforcementClient for testing
// cfBanExecutor.ExecuteBan without a real Cloudflare API.
type fakeEnforcementClient struct {
	ruleID string
}

func (f *fakeEnforcementClient) DiscoverIPAccessRules(ctx context.Context, zoneID string, provenance snapshot.ProvenanceMetadata) (snapshot.Snapshot, error) {
	return snapshot.Snapshot{}, nil
}
func (f *fakeEnforcementClient) ListIPAccessRulesByTag(ctx context.Context, zoneID, tag string) (map[string]string, error) {
	return nil, nil
}
func (f *fakeEnforcementClient) ListIPAccessRulesByNotePrefix(ctx context.Context, zoneID, prefix string) ([]models.IPAccessRule, error) {
	return nil, nil
}
func (f *fakeEnforcementClient) AddIPAccessRule(ctx context.Context, zoneID, value, notes, target string) (string, error) {
	return f.ruleID, nil
}
func (f *fakeEnforcementClient) DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error {
	return nil
}

var _ cfpkg.EnforcementClient = (*fakeEnforcementClient)(nil)

// fakeLifecycleStore is a minimal banlifecycle.Store recording every Upsert
// call so tests can inspect the Entry that was persisted.
type fakeLifecycleStore struct {
	upserted []banlifecycle.Entry
}

func (s *fakeLifecycleStore) Upsert(_ context.Context, e banlifecycle.Entry) error {
	s.upserted = append(s.upserted, e)
	return nil
}
func (s *fakeLifecycleStore) Get(_ context.Context, ip string) (banlifecycle.Entry, bool, error) {
	return banlifecycle.Entry{}, false, nil
}
func (s *fakeLifecycleStore) Active(_ context.Context) ([]banlifecycle.Entry, error) {
	return nil, nil
}
func (s *fakeLifecycleStore) Expired(_ context.Context, _ time.Time) ([]banlifecycle.Entry, error) {
	return nil, nil
}
func (s *fakeLifecycleStore) MarkStatus(_ context.Context, ip, status, note string) error {
	return nil
}
func (s *fakeLifecycleStore) RecidiveLevel(_ context.Context, ip string) (int, error) {
	return 0, nil
}

var _ banlifecycle.Store = (*fakeLifecycleStore)(nil)

// TestCFBanExecutor_PropagatesConfidenceToLifecycleEntry guards against a
// regression of the bug where BanDecision.Confidence existed but was never
// copied into the persisted banlifecycle.Entry. If Entry.Confidence stays 0
// for a confidence_100 ban, internal/security/autodeban's evaluateEntry
// treats the ban as "weak_signal_ban" and auto-debans it almost immediately
// regardless of how hostile the IP actually is — silently defeating the
// AbuseIPDB-corroborated ban path.
func TestCFBanExecutor_PropagatesConfidenceToLifecycleEntry(t *testing.T) {
	store := &fakeLifecycleStore{}
	exec := &cfBanExecutor{
		client:         &fakeEnforcementClient{ruleID: "rule-123"},
		zoneID:         "zone-1",
		lifecycleStore: store,
		now:            func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
	}

	decision := autoban.BanDecision{
		IP:         "203.0.113.9",
		ShouldBan:  true,
		Reason:     "confidence_100",
		Confidence: 100,
	}

	if err := exec.ExecuteBan(context.Background(), decision); err != nil {
		t.Fatalf("ExecuteBan: unexpected error: %v", err)
	}

	if len(store.upserted) != 1 {
		t.Fatalf("expected exactly one lifecycle entry upserted, got %d", len(store.upserted))
	}
	entry := store.upserted[0]
	if entry.Confidence != 100 {
		t.Errorf("expected Entry.Confidence=100 propagated from BanDecision.Confidence, got %d", entry.Confidence)
	}
	if entry.IP != decision.IP {
		t.Errorf("expected Entry.IP=%q, got %q", decision.IP, entry.IP)
	}
	if entry.RuleID != "rule-123" {
		t.Errorf("expected Entry.RuleID propagated from AddIPAccessRule result, got %q", entry.RuleID)
	}
}

// TestCFBanExecutor_BurstBanLeavesConfidenceZero documents the intentional
// counterpart: burst-based bans have no AbuseIPDB corroboration, so
// Entry.Confidence is correctly left at 0 (treated as a local-only/weak
// signal by autodeban, which is by design for this path).
func TestCFBanExecutor_BurstBanLeavesConfidenceZero(t *testing.T) {
	store := &fakeLifecycleStore{}
	exec := &cfBanExecutor{
		client:         &fakeEnforcementClient{ruleID: "rule-456"},
		zoneID:         "zone-1",
		lifecycleStore: store,
		now:            func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
	}

	decision := autoban.BanDecision{
		IP:        "203.0.113.10",
		ShouldBan: true,
		Reason:    "burst_malicious",
		// Confidence intentionally left unset (0): burst path never
		// consults AbuseIPDB.
	}

	if err := exec.ExecuteBan(context.Background(), decision); err != nil {
		t.Fatalf("ExecuteBan: unexpected error: %v", err)
	}

	if len(store.upserted) != 1 {
		t.Fatalf("expected exactly one lifecycle entry upserted, got %d", len(store.upserted))
	}
	if got := store.upserted[0].Confidence; got != 0 {
		t.Errorf("expected Entry.Confidence=0 for burst-only ban, got %d", got)
	}
}
