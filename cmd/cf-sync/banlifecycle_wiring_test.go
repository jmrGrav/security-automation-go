package main

import (
	"context"
	"fmt"
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
//
// duplicateFor, when set, makes AddIPAccessRule simulate Cloudflare's
// "firewallaccessrules.api.duplicate_of_existing" (code 10009) response for
// that IP instead of creating a new rule. existingRules is then consulted by
// ListIPAccessRulesByNotePrefix to simulate the pre-existing rule the
// duplicate response refers to.
type fakeEnforcementClient struct {
	ruleID        string
	duplicateFor  string
	existingRules []models.IPAccessRule
}

func (f *fakeEnforcementClient) DiscoverIPAccessRules(ctx context.Context, zoneID string, provenance snapshot.ProvenanceMetadata) (snapshot.Snapshot, error) {
	return snapshot.Snapshot{}, nil
}
func (f *fakeEnforcementClient) ListIPAccessRulesByTag(ctx context.Context, zoneID, tag string) (map[string]string, error) {
	return nil, nil
}
func (f *fakeEnforcementClient) ListIPAccessRulesByNotePrefix(ctx context.Context, zoneID, prefix string) ([]models.IPAccessRule, error) {
	return f.existingRules, nil
}
func (f *fakeEnforcementClient) AddIPAccessRule(ctx context.Context, zoneID, value, notes, target string) (string, error) {
	if f.duplicateFor != "" && value == f.duplicateFor {
		return "", fmt.Errorf("cloudflare.Client.AddIPAccessRuleWithMode %s: Cloudflare mutation error: [{Code:10009 Message:firewallaccessrules.api.duplicate_of_existing}]", value)
	}
	return f.ruleID, nil
}
func (f *fakeEnforcementClient) AddIPAccessRuleWithMode(ctx context.Context, zoneID, value, notes, target, mode string) (string, error) {
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
func (s *fakeLifecycleStore) Recent(_ context.Context, _ int) ([]banlifecycle.Entry, error) {
	return nil, nil
}
func (s *fakeLifecycleStore) MarkStatus(_ context.Context, ip, status, note string) error {
	return nil
}
func (s *fakeLifecycleStore) RecordCleanupFailure(_ context.Context, ip, errMsg string) error {
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

// TestCFBanExecutor_FreshBanSucceeds is a baseline regression guard for the
// non-duplicate path: AddIPAccessRule succeeds, ExecuteBan returns nil, and a
// lifecycle entry is upserted with the freshly-created rule ID.
func TestCFBanExecutor_FreshBanSucceeds(t *testing.T) {
	store := &fakeLifecycleStore{}
	exec := &cfBanExecutor{
		client:         &fakeEnforcementClient{ruleID: "rule-fresh"},
		zoneID:         "zone-1",
		lifecycleStore: store,
		now:            func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
	}

	decision := autoban.BanDecision{
		IP:         "203.0.113.20",
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
	if got := store.upserted[0].RuleID; got != "rule-fresh" {
		t.Errorf("expected Entry.RuleID=%q, got %q", "rule-fresh", got)
	}
}

// TestCFBanExecutor_DuplicateRuleTreatedAsIdempotentSuccess is the
// regression test for the retry-storm bug: when Cloudflare reports
// duplicate_of_existing (code 10009) for an IP that's already banned,
// ExecuteBan must:
//  1. return nil (not an error), so callers' "RecordBan only if ExecuteBan
//     == nil" pattern marks the IP as banned in the dedup store and the
//     retry storm stops; and
//  2. still backfill a banlifecycle.Entry, resolving the existing rule's
//     real ID via ListIPAccessRulesByNotePrefix rather than skipping
//     lifecycle bookkeeping entirely.
func TestCFBanExecutor_DuplicateRuleTreatedAsIdempotentSuccess(t *testing.T) {
	ip := "74.248.112.30"
	existingCreatedAt := time.Date(2026, 6, 20, 8, 0, 0, 0, time.UTC)

	client := &fakeEnforcementClient{
		duplicateFor: ip,
		existingRules: []models.IPAccessRule{
			{
				ID:    "rule-existing-999",
				Notes: "cf-sync:autoban:confidence_100:exp=2026-06-20T09:00:00Z",
				Configuration: models.RuleConfiguration{
					Target: "ip",
					Value:  ip,
				},
				CreatedOn: existingCreatedAt,
			},
		},
	}
	store := &fakeLifecycleStore{}
	exec := &cfBanExecutor{
		client:         client,
		zoneID:         "zone-1",
		lifecycleStore: store,
		now:            func() time.Time { return time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC) },
	}

	decision := autoban.BanDecision{
		IP:         ip,
		ShouldBan:  true,
		Reason:     "confidence_100",
		Confidence: 100,
	}

	err := exec.ExecuteBan(context.Background(), decision)
	if err != nil {
		t.Fatalf("ExecuteBan: expected nil error on duplicate_of_existing (idempotent success), got: %v", err)
	}

	if len(store.upserted) != 1 {
		t.Fatalf("expected exactly one lifecycle entry upserted (backfilled), got %d", len(store.upserted))
	}
	entry := store.upserted[0]
	if entry.RuleID != "rule-existing-999" {
		t.Errorf("expected backfilled Entry.RuleID to be the looked-up existing rule ID %q, got %q", "rule-existing-999", entry.RuleID)
	}
	if entry.IP != ip {
		t.Errorf("expected Entry.IP=%q, got %q", ip, entry.IP)
	}
	if !entry.CreatedAt.Equal(existingCreatedAt) {
		t.Errorf("expected Entry.CreatedAt to use the existing rule's real CreatedOn (%v), got %v", existingCreatedAt, entry.CreatedAt)
	}
}

// TestCFBanExecutor_DuplicateRuleLookupMissFallsBackToNow guards the
// secondary fallback path: if the existing rule can't be resolved (e.g. it
// predates cf-sync's note-prefix convention, or the list call fails), the
// duplicate is still treated as idempotent success (no retry storm), the
// lifecycle entry is still backfilled, and "now" is used as the documented
// fallback creation time since the real creation time isn't knowable.
func TestCFBanExecutor_DuplicateRuleLookupMissFallsBackToNow(t *testing.T) {
	ip := "185.93.89.167"
	now := time.Date(2026, 6, 22, 12, 0, 0, 0, time.UTC)

	client := &fakeEnforcementClient{
		duplicateFor:  ip,
		existingRules: nil, // lookup miss: no rule found with this IP under the autoban note prefix
	}
	store := &fakeLifecycleStore{}
	exec := &cfBanExecutor{
		client:         client,
		zoneID:         "zone-1",
		lifecycleStore: store,
		now:            func() time.Time { return now },
	}

	decision := autoban.BanDecision{
		IP:        ip,
		ShouldBan: true,
		Reason:    "burst_malicious",
	}

	if err := exec.ExecuteBan(context.Background(), decision); err != nil {
		t.Fatalf("ExecuteBan: expected nil error on duplicate_of_existing even when lookup misses, got: %v", err)
	}

	if len(store.upserted) != 1 {
		t.Fatalf("expected exactly one lifecycle entry upserted, got %d", len(store.upserted))
	}
	entry := store.upserted[0]
	if entry.RuleID != "" {
		t.Errorf("expected empty Entry.RuleID when lookup misses, got %q", entry.RuleID)
	}
	if !entry.CreatedAt.Equal(now) {
		t.Errorf("expected Entry.CreatedAt to fall back to now (%v) when real creation time is unknown, got %v", now, entry.CreatedAt)
	}
}
