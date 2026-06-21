package cleanup

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle/memstore"
)

// fakeCF is a fake Cloudflare client that records every delete call, for
// asserting deletes are scoped exactly to tracked entries.
type fakeCF struct {
	rules      []CFRule
	deletedIDs []string
	deleteErr  map[string]error // ruleID -> error to return
	listErr    error
}

func (f *fakeCF) ListAutobanRules(ctx context.Context, zoneID string) ([]CFRule, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.rules, nil
}

func (f *fakeCF) DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error {
	f.deletedIDs = append(f.deletedIDs, ruleID)
	if err, ok := f.deleteErr[ruleID]; ok {
		return err
	}
	return nil
}

type fakeAudit struct {
	calls []banlifecycle.Entry
}

func (a *fakeAudit) RecordDeban(ctx context.Context, e banlifecycle.Entry, reason string) error {
	a.calls = append(a.calls, e)
	return nil
}

type fakeEvidence struct {
	calls []banlifecycle.Entry
}

func (ev *fakeEvidence) RecordDebanEvidence(ctx context.Context, e banlifecycle.Entry, reason string) error {
	ev.calls = append(ev.calls, e)
	return nil
}

func TestWorker_ExpiredFirstBan_DeletesRuleAndMarksCleaned(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:            "1.2.3.4",
		Source:        "autoban_confidence_100",
		Reason:        "confidence_100",
		CreatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-1 * time.Hour), // 1h ban created 2h ago: expired
		Duration:      1 * time.Hour,
		RuleID:        "rule-1",
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cf := &fakeCF{}
	audit := &fakeAudit{}
	evidence := &fakeEvidence{}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Audit: audit, Evidence: evidence, Now: func() time.Time { return now }}

	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(cf.deletedIDs) != 1 || cf.deletedIDs[0] != "rule-1" {
		t.Fatalf("expected delete of rule-1, got %v", cf.deletedIDs)
	}
	got, ok, err := store.Get(context.Background(), "1.2.3.4")
	if err != nil || !ok {
		t.Fatalf("Get: %v ok=%v", err, ok)
	}
	if got.Status != banlifecycle.StatusExpiredCleaned {
		t.Fatalf("expected status expired_cleaned, got %q", got.Status)
	}
	if len(audit.calls) != 1 {
		t.Fatalf("expected 1 audit call, got %d", len(audit.calls))
	}
	if len(evidence.calls) != 1 {
		t.Fatalf("expected 1 evidence call, got %d", len(evidence.calls))
	}
}

func TestWorker_RecidiveLevel2_NotYetExpired_LeavesRuleAlone(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:            "2.2.2.2",
		CreatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(23 * time.Hour), // 24h ban created 1h ago: not expired
		Duration:      24 * time.Hour,
		RuleID:        "rule-2",
		RecidiveLevel: 2,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	expired, err := store.Expired(context.Background(), now)
	if err != nil {
		t.Fatalf("Expired: %v", err)
	}
	if len(expired) != 0 {
		t.Fatalf("expected no expired entries, got %d", len(expired))
	}

	cf := &fakeCF{}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(cf.deletedIDs) != 0 {
		t.Fatalf("expected no deletes, got %v", cf.deletedIDs)
	}
}

func TestWorker_RecidiveLevel3_NotYetExpired_LeavesRuleAlone(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:            "3.3.3.3",
		CreatedAt:     now.Add(-1 * time.Hour),
		ExpiresAt:     now.Add(167 * time.Hour), // 168h ban created 1h ago: not expired
		Duration:      168 * time.Hour,
		RuleID:        "rule-3",
		RecidiveLevel: 3,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cf := &fakeCF{}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(cf.deletedIDs) != 0 {
		t.Fatalf("expected no deletes, got %v", cf.deletedIDs)
	}
}

func TestWorker_NeverDeletesUntrackedRule(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	// One tracked, expired entry with empty RuleID (forces fallback lookup).
	tracked := banlifecycle.Entry{
		IP:            "4.4.4.4",
		CreatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-1 * time.Hour),
		Duration:      1 * time.Hour,
		RuleID:        "",
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), tracked); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	// Mixed list of CF rules: one matching the tracked IP via autoban note
	// prefix, one manually-created rule, one CrowdSec-driven rule with a
	// different note prefix. Only the first must ever be deleted.
	cf := &fakeCF{
		rules: []CFRule{
			{ID: "rule-tracked", Notes: AutobanNotePrefix + "confidence_100:exp=2026-06-21T11:00:00Z", IP: "4.4.4.4"},
			{ID: "rule-manual", Notes: "manually added by operator", IP: "5.5.5.5"},
			{ID: "rule-crowdsec", Notes: "crowdsec-local-ban", IP: "6.6.6.6"},
		},
	}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(cf.deletedIDs) != 1 || cf.deletedIDs[0] != "rule-tracked" {
		t.Fatalf("expected exactly one delete of rule-tracked, got %v", cf.deletedIDs)
	}
	for _, id := range cf.deletedIDs {
		if id == "rule-manual" || id == "rule-crowdsec" {
			t.Fatalf("must never delete untracked rule %s", id)
		}
	}
}

func TestWorker_EmptyRuleID_FallsBackToNoteBasedLookup(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:            "7.7.7.7",
		Reason:        "confidence_100",
		CreatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-1 * time.Hour),
		Duration:      1 * time.Hour,
		RuleID:        "", // forces fallback
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	expNote := fmt.Sprintf("%sconfidence_100:exp=%s", AutobanNotePrefix, now.Add(-1*time.Hour).Format(time.RFC3339))
	cf := &fakeCF{
		rules: []CFRule{
			{ID: "rule-other", Notes: AutobanNotePrefix + "burst_malicious:exp=2026-06-22T00:00:00Z", IP: "8.8.8.8"},
			{ID: "rule-match", Notes: expNote, IP: "7.7.7.7"},
		},
	}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if len(cf.deletedIDs) != 1 || cf.deletedIDs[0] != "rule-match" {
		t.Fatalf("expected delete of rule-match via note fallback, got %v", cf.deletedIDs)
	}
	got, ok, _ := store.Get(context.Background(), "7.7.7.7")
	if !ok || got.Status != banlifecycle.StatusExpiredCleaned {
		t.Fatalf("expected entry marked expired_cleaned, got %+v ok=%v", got, ok)
	}
}

func TestWorker_IdempotentRerun_NoDoubleDelete(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:            "9.9.9.9",
		CreatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-1 * time.Hour),
		Duration:      1 * time.Hour,
		RuleID:        "rule-9",
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cf := &fakeCF{}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}

	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}

	if len(cf.deletedIDs) != 1 {
		t.Fatalf("expected exactly 1 delete across two runs, got %d: %v", len(cf.deletedIDs), cf.deletedIDs)
	}
}

func TestWorker_IdempotentRerun_404TreatedAsSuccess(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:            "10.10.10.10",
		CreatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-1 * time.Hour),
		Duration:      1 * time.Hour,
		RuleID:        "rule-10",
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cf := &fakeCF{deleteErr: map[string]error{"rule-10": fmt.Errorf("cloudflare: HTTP 404: rule not found")}}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got, ok, _ := store.Get(context.Background(), "10.10.10.10")
	if !ok || got.Status != banlifecycle.StatusExpiredCleaned {
		t.Fatalf("expected entry marked expired_cleaned despite 404, got %+v ok=%v", got, ok)
	}
}
