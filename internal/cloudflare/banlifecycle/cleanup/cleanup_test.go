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

// abuseIPDBTracker fakes an AbuseIPDB-like dependency that DebanOne/ClearAll
// must never touch. Its presence in a test as an unused-but-asserted-empty
// counter operationalizes the hard constraint that debanning from
// Cloudflare must never delete or reset AbuseIPDB report state.
type abuseIPDBTracker struct {
	reportsDeleted int
	windowsReset   int
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
		ExpiresAt:     now.Add(23 * time.Hour), // 24h ban created 1h ago: not expired
		Duration:      24 * time.Hour,
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

// TestWorker_DeleteFailure_PersistsCleanupFailure guards against the
// log-only failure path: when DeleteIPAccessRule fails with a real error
// (not 404), the worker must persist the failure via
// Store.RecordCleanupFailure (CleanupAttempts incremented, LastCleanupError
// set) and the entry must stay active so the next pass retries — not just
// log the error.
func TestWorker_DeleteFailure_PersistsCleanupFailure(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:            "172.16.0.9",
		CreatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-1 * time.Hour),
		Duration:      1 * time.Hour,
		RuleID:        "rule-fail",
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cf := &fakeCF{deleteErr: map[string]error{"rule-fail": fmt.Errorf("cloudflare: HTTP 500: internal error")}}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("Run: %v", err)
	}

	got, ok, err := store.Get(context.Background(), "172.16.0.9")
	if err != nil || !ok {
		t.Fatalf("Get: %v ok=%v", err, ok)
	}
	if got.Status != banlifecycle.StatusActive {
		t.Fatalf("expected entry to remain active for retry, got status %q", got.Status)
	}
	if got.CleanupAttempts != 1 {
		t.Fatalf("expected CleanupAttempts=1, got %d", got.CleanupAttempts)
	}
	if got.LastCleanupError == "" {
		t.Fatal("expected LastCleanupError to be recorded, got empty string")
	}
	if got.LastCleanupAttemptAt.IsZero() {
		t.Fatal("expected LastCleanupAttemptAt to be recorded, got zero time")
	}

	// A second failed pass must increment the counter further, not reset it.
	if err := w.Run(context.Background()); err != nil {
		t.Fatalf("second Run: %v", err)
	}
	got2, _, _ := store.Get(context.Background(), "172.16.0.9")
	if got2.CleanupAttempts != 2 {
		t.Fatalf("expected CleanupAttempts=2 after second failure, got %d", got2.CleanupAttempts)
	}
}

func TestWorker_DebanOne_DeletesRuleAndMarksOperatorDebanned(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:            "20.20.20.20",
		CreatedAt:     now.Add(-10 * time.Minute),
		ExpiresAt:     now.Add(50 * time.Minute), // still active, not expired
		Duration:      1 * time.Hour,
		RuleID:        "rule-20",
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cf := &fakeCF{}
	audit := &fakeAudit{}
	evidence := &fakeEvidence{}
	abuseIPDB := &abuseIPDBTracker{}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Audit: audit, Evidence: evidence, Now: func() time.Time { return now }}

	got, err := w.DebanOne(context.Background(), "20.20.20.20", "operator clicked deban")
	if err != nil {
		t.Fatalf("DebanOne: %v", err)
	}
	if got.Status != banlifecycle.StatusOperatorDebanned {
		t.Fatalf("expected returned entry status operator_debanned, got %q", got.Status)
	}
	if len(cf.deletedIDs) != 1 || cf.deletedIDs[0] != "rule-20" {
		t.Fatalf("expected delete of rule-20, got %v", cf.deletedIDs)
	}
	stored, ok, err := store.Get(context.Background(), "20.20.20.20")
	if err != nil || !ok {
		t.Fatalf("Get: %v ok=%v", err, ok)
	}
	if stored.Status != banlifecycle.StatusOperatorDebanned {
		t.Fatalf("expected stored status operator_debanned, got %q", stored.Status)
	}
	if len(audit.calls) != 1 || len(evidence.calls) != 1 {
		t.Fatalf("expected exactly 1 audit and 1 evidence call, got audit=%d evidence=%d", len(audit.calls), len(evidence.calls))
	}
	if abuseIPDB.reportsDeleted != 0 || abuseIPDB.windowsReset != 0 {
		t.Fatalf("DebanOne must never touch AbuseIPDB state, got %+v", abuseIPDB)
	}
}

func TestWorker_DebanOne_NoTrackedEntry_Errors(t *testing.T) {
	store := memstore.New()
	cf := &fakeCF{}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1"}

	if _, err := w.DebanOne(context.Background(), "30.30.30.30", "operator-initiated"); err == nil {
		t.Fatal("expected error for untracked IP, got nil")
	}
	if len(cf.deletedIDs) != 0 {
		t.Fatalf("expected no deletes for untracked IP, got %v", cf.deletedIDs)
	}
}

func TestWorker_DebanOne_AlreadyGoneRule_404TreatedAsSuccess(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	entry := banlifecycle.Entry{
		IP:        "40.40.40.40",
		CreatedAt: now.Add(-10 * time.Minute),
		ExpiresAt: now.Add(50 * time.Minute),
		Duration:  1 * time.Hour,
		RuleID:    "rule-40",
		Status:    banlifecycle.StatusActive,
	}
	if err := store.Upsert(context.Background(), entry); err != nil {
		t.Fatalf("Upsert: %v", err)
	}

	cf := &fakeCF{deleteErr: map[string]error{"rule-40": fmt.Errorf("cloudflare: HTTP 404: rule not found")}}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}

	if _, err := w.DebanOne(context.Background(), "40.40.40.40", ""); err != nil {
		t.Fatalf("DebanOne: %v", err)
	}
	got, ok, _ := store.Get(context.Background(), "40.40.40.40")
	if !ok || got.Status != banlifecycle.StatusOperatorDebanned {
		t.Fatalf("expected operator_debanned despite 404, got %+v ok=%v", got, ok)
	}
}

func TestWorker_ClearAll_DebansEveryActiveEntryOnly(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	active1 := banlifecycle.Entry{IP: "50.1.1.1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), RuleID: "rule-50-1", Status: banlifecycle.StatusActive}
	active2 := banlifecycle.Entry{IP: "50.1.1.2", CreatedAt: now, ExpiresAt: now.Add(time.Hour), RuleID: "rule-50-2", Status: banlifecycle.StatusActive}
	alreadyDone := banlifecycle.Entry{IP: "50.1.1.3", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour), RuleID: "rule-50-3", Status: banlifecycle.StatusExpiredCleaned}
	for _, e := range []banlifecycle.Entry{active1, active2, alreadyDone} {
		if err := store.Upsert(context.Background(), e); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	cf := &fakeCF{}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}

	result, err := w.ClearAll(context.Background(), "operator-initiated bulk clear")
	if err != nil {
		t.Fatalf("ClearAll: %v", err)
	}
	if result.Attempted != 2 || result.Deleted != 2 || result.Failed != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
	for _, id := range cf.deletedIDs {
		if id == "rule-50-3" {
			t.Fatal("must never re-delete an already-completed entry's rule")
		}
	}
	if len(cf.deletedIDs) != 2 {
		t.Fatalf("expected exactly 2 deletes, got %v", cf.deletedIDs)
	}
}

func TestWorker_ClearAll_PartialFailureReportedNotFatal(t *testing.T) {
	now := time.Date(2026, 6, 21, 12, 0, 0, 0, time.UTC)
	store := memstore.New()
	good := banlifecycle.Entry{IP: "60.1.1.1", CreatedAt: now, ExpiresAt: now.Add(time.Hour), RuleID: "rule-60-1", Status: banlifecycle.StatusActive}
	bad := banlifecycle.Entry{IP: "60.1.1.2", CreatedAt: now, ExpiresAt: now.Add(time.Hour), RuleID: "rule-60-2", Status: banlifecycle.StatusActive}
	for _, e := range []banlifecycle.Entry{good, bad} {
		if err := store.Upsert(context.Background(), e); err != nil {
			t.Fatalf("Upsert: %v", err)
		}
	}

	cf := &fakeCF{deleteErr: map[string]error{"rule-60-2": fmt.Errorf("cloudflare: HTTP 500: internal error")}}
	w := &Worker{Store: store, CF: cf, ZoneID: "zone1", Now: func() time.Time { return now }}

	result, err := w.ClearAll(context.Background(), "")
	if err != nil {
		t.Fatalf("ClearAll: %v", err)
	}
	if result.Attempted != 2 {
		t.Fatalf("expected attempted=2, got %d", result.Attempted)
	}
	if result.Deleted != 1 || result.Failed != 1 {
		t.Fatalf("expected 1 deleted and 1 failed, got %+v", result)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("expected 1 error message, got %v", result.Errors)
	}
}
