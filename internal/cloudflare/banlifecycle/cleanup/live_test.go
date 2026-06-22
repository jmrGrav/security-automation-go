//go:build livecleanup

// This file implements Mission 1's mandatory "live-controlled cleanup test":
// a real Cloudflare API run of the cleanup worker, scoped to RFC 5737
// TEST-NET-1 addresses (192.0.2.0/24 — reserved for documentation, never a
// real visitor), verifying:
//
//  1. an expired managed (cf-sync:autoban:) rule is actually deleted via the
//     live Cloudflare API,
//  2. an audit + evidence record is written for that deban, and
//  3. a manually-created rule (no autoban note prefix) on the same zone is
//     left completely untouched.
//
// It never runs as part of `go test ./...` — it requires both the
// "livecleanup" build tag and CF_API_TOKEN/CF_ZONE_ID to be set, e.g.:
//
//	CF_API_TOKEN=... CF_ZONE_ID=... go test -tags=livecleanup -run TestLiveCleanup -v ./internal/cloudflare/banlifecycle/cleanup/
package cleanup

import (
	"context"
	"os"
	"testing"
	"time"

	cfpkg "github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle/memstore"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/httpclient"
)

type liveCleanupAdapter struct {
	client cfpkg.EnforcementClient
}

func (a *liveCleanupAdapter) ListAutobanRules(ctx context.Context, zoneID string) ([]CFRule, error) {
	rules, err := a.client.ListIPAccessRulesByNotePrefix(ctx, zoneID, AutobanNotePrefix)
	if err != nil {
		return nil, err
	}
	out := make([]CFRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, CFRule{ID: r.ID, Notes: r.Notes, IP: r.Configuration.Value})
	}
	return out, nil
}

func (a *liveCleanupAdapter) DeleteIPAccessRule(ctx context.Context, zoneID, ruleID string) error {
	return a.client.DeleteIPAccessRule(ctx, zoneID, ruleID)
}

var _ CFClient = (*liveCleanupAdapter)(nil)

type recordingAuditSink struct {
	calls []banlifecycle.Entry
}

func (s *recordingAuditSink) RecordDeban(_ context.Context, e banlifecycle.Entry, _ string) error {
	s.calls = append(s.calls, e)
	return nil
}

type recordingEvidenceSink struct {
	calls []banlifecycle.Entry
}

func (s *recordingEvidenceSink) RecordDebanEvidence(_ context.Context, e banlifecycle.Entry, _ string) error {
	s.calls = append(s.calls, e)
	return nil
}

// TestLiveCleanup_DeletesExpiredManagedRule_LeavesManualRuleUntouched is the
// Mission 1 mandatory live-controlled cleanup test. It mutates a real
// Cloudflare zone (creating and deleting access rules scoped to TEST-NET-1
// addresses only) and is intentionally excluded from normal `go test ./...`.
func TestLiveCleanup_DeletesExpiredManagedRule_LeavesManualRuleUntouched(t *testing.T) {
	token := os.Getenv("CF_API_TOKEN")
	zoneID := os.Getenv("CF_ZONE_ID")
	if token == "" || zoneID == "" {
		t.Skip("CF_API_TOKEN and CF_ZONE_ID must be set to run the live cleanup test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	hc := httpclient.New(config.HTTPConfig{Timeout: 15 * time.Second})
	cf := cfpkg.NewClient(hc, token)

	stamp := time.Now().UTC().Format("20060102T150405Z")

	// Managed rule: tagged with the real autoban note prefix, on a
	// TEST-NET-1 address (RFC 5737) that can never belong to a real visitor.
	managedIP := "192.0.2.55"
	managedNote := AutobanNotePrefix + "live-validation-test:" + stamp
	managedRuleID, err := cf.AddIPAccessRule(ctx, zoneID, managedIP, managedNote, "ip")
	if err != nil {
		t.Fatalf("create managed test rule: %v", err)
	}
	t.Logf("created managed test rule %s for %s", managedRuleID, managedIP)

	// Manual-style rule: deliberately NOT tagged with the autoban prefix,
	// simulating an operator-created rule that must never be touched by
	// the cleanup worker. Cleaned up unconditionally at the end of the test.
	manualIP := "192.0.2.66"
	manualNote := "manual-test-rule-do-not-touch:" + stamp
	manualRuleID, err := cf.AddIPAccessRule(ctx, zoneID, manualIP, manualNote, "ip")
	if err != nil {
		t.Fatalf("create manual test rule: %v", err)
	}
	t.Logf("created manual test rule %s for %s", manualRuleID, manualIP)
	defer func() {
		if delErr := cf.DeleteIPAccessRule(context.Background(), zoneID, manualRuleID); delErr != nil {
			t.Logf("cleanup: failed to delete manual test rule %s: %v", manualRuleID, delErr)
		}
	}()

	store := memstore.New()
	now := time.Now().UTC()
	entry := banlifecycle.Entry{
		IP:            managedIP,
		Source:        "live_validation_test",
		Reason:        "mission1_live_cleanup_validation",
		Confidence:    100,
		CreatedAt:     now.Add(-2 * time.Hour),
		ExpiresAt:     now.Add(-1 * time.Hour), // already expired
		Duration:      time.Hour,
		RuleID:        managedRuleID,
		RecidiveLevel: 1,
		Status:        banlifecycle.StatusActive,
	}
	if err := store.Upsert(ctx, entry); err != nil {
		t.Fatalf("seed lifecycle entry: %v", err)
	}

	audit := &recordingAuditSink{}
	evidence := &recordingEvidenceSink{}
	worker := &Worker{
		Store:    store,
		CF:       &liveCleanupAdapter{client: cf},
		ZoneID:   zoneID,
		Audit:    audit,
		Evidence: evidence,
		Now:      func() time.Time { return now },
	}

	if err := worker.Run(ctx); err != nil {
		t.Fatalf("worker.Run: %v", err)
	}

	// 1. The managed rule must actually be gone from the live zone.
	remaining, err := cf.ListIPAccessRulesByNotePrefix(ctx, zoneID, AutobanNotePrefix)
	if err != nil {
		t.Fatalf("list autoban rules after cleanup: %v", err)
	}
	for _, r := range remaining {
		if r.ID == managedRuleID {
			t.Fatalf("expected managed rule %s to be deleted from live zone, but it is still present", managedRuleID)
		}
	}

	// 2. An audit + evidence record must have been written for the deban.
	if len(audit.calls) != 1 || audit.calls[0].IP != managedIP {
		t.Fatalf("expected exactly one audit record for %s, got %+v", managedIP, audit.calls)
	}
	if len(evidence.calls) != 1 || evidence.calls[0].IP != managedIP {
		t.Fatalf("expected exactly one evidence record for %s, got %+v", managedIP, evidence.calls)
	}

	// 3. Local lifecycle state must reflect the cleanup.
	got, ok, err := store.Get(ctx, managedIP)
	if err != nil || !ok {
		t.Fatalf("Get after cleanup: err=%v ok=%v", err, ok)
	}
	if got.Status != banlifecycle.StatusExpiredCleaned {
		t.Fatalf("expected status expired_cleaned, got %q", got.Status)
	}

	// 4. The manual (unmanaged) rule must be completely untouched.
	manualRules, err := cf.ListIPAccessRulesByNotePrefix(ctx, zoneID, "manual-test-rule-do-not-touch")
	if err != nil {
		t.Fatalf("list manual test rule: %v", err)
	}
	found := false
	for _, r := range manualRules {
		if r.ID == manualRuleID {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected manual rule %s for %s to remain untouched by cleanup worker, but it is gone", manualRuleID, manualIP)
	}
}
