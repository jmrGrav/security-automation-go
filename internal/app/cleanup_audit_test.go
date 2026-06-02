package app

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/snapshot"
)

type cleanupFakeCloudflare struct {
	rules         map[string]string
	deleteErr     error
	listErr       error
	deleteCalls   []string
	zoneIDs       []string
	discoverCalls int
	addCalls      int
	onDelete      func()
}

func (f *cleanupFakeCloudflare) DiscoverIPAccessRules(context.Context, string, snapshot.ProvenanceMetadata) (snapshot.Snapshot, error) {
	f.discoverCalls++
	return snapshot.Snapshot{}, nil
}

func (f *cleanupFakeCloudflare) ListIPAccessRulesByTag(_ context.Context, zoneID, _ string) (map[string]string, error) {
	f.zoneIDs = append(f.zoneIDs, zoneID)
	if f.listErr != nil {
		return nil, f.listErr
	}
	out := make(map[string]string, len(f.rules))
	for ip, ruleID := range f.rules {
		out[ip] = ruleID
	}
	return out, nil
}

func (f *cleanupFakeCloudflare) AddIPAccessRule(context.Context, string, string, string, string) (string, error) {
	f.addCalls++
	return "rule-id", nil
}

func (f *cleanupFakeCloudflare) DeleteIPAccessRule(_ context.Context, zoneID, ruleID string) error {
	f.zoneIDs = append(f.zoneIDs, zoneID)
	f.deleteCalls = append(f.deleteCalls, ruleID)
	for ip, existing := range f.rules {
		if existing == ruleID {
			delete(f.rules, ip)
		}
	}
	if f.onDelete != nil {
		f.onDelete()
	}
	return f.deleteErr
}

type cleanupFakeCrowdSec struct {
	activeBans []string
	err        error
}

func (f *cleanupFakeCrowdSec) ListActiveBans(context.Context) ([]string, error) {
	return append([]string(nil), f.activeBans...), f.err
}

func (f *cleanupFakeCrowdSec) ListRecentBans(context.Context) ([]csmodels.RecentBan, error) {
	return nil, nil
}

func TestCleanupAppDeletesOnlyStaleCloudflareRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"
	app := &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf: &cleanupFakeCloudflare{rules: map[string]string{
			"1.2.3.4": "keep-rule",
			"5.6.7.8": "delete-rule",
		}},
		cs: &cleanupFakeCrowdSec{activeBans: []string{"1.2.3.4"}},
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("cleanup run: %v", err)
	}

	cf := app.cf.(*cleanupFakeCloudflare)
	if len(cf.deleteCalls) != 1 || cf.deleteCalls[0] != "delete-rule" {
		t.Fatalf("expected only stale rule deletion, got %+v", cf.deleteCalls)
	}
}

func TestCleanupAppReturnsErrorWhenCloudflareDeleteFails(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"
	app := &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf: &cleanupFakeCloudflare{
			rules:     map[string]string{"5.6.7.8": "delete-rule"},
			deleteErr: errors.New("cloudflare delete failed"),
		},
		cs: &cleanupFakeCrowdSec{activeBans: nil},
	}

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("expected cleanup to fail when cloudflare delete fails")
	}

	cf := app.cf.(*cleanupFakeCloudflare)
	if len(cf.deleteCalls) != 1 || cf.deleteCalls[0] != "delete-rule" {
		t.Fatalf("expected delete attempt on stale rule, got %+v", cf.deleteCalls)
	}
}

func TestCleanupAppDoesNotDeleteOwnedRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"
	app := &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf: &cleanupFakeCloudflare{rules: map[string]string{
			"1.2.3.4": "keep-rule",
		}},
		cs: &cleanupFakeCrowdSec{activeBans: []string{"1.2.3.4"}},
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("cleanup run: %v", err)
	}

	cf := app.cf.(*cleanupFakeCloudflare)
	if len(cf.deleteCalls) != 0 {
		t.Fatalf("expected no deletes for owned rules, got %+v", cf.deleteCalls)
	}
}

func TestCleanupAppDryRunDoesNotDeleteAndReportsStaleRules(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"
	cf := &cleanupFakeCloudflare{rules: map[string]string{
		"1.2.3.4": "keep-rule",
		"5.6.7.8": "delete-rule",
	}}
	app := &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf:     cf,
		cs:     &cleanupFakeCrowdSec{activeBans: []string{"1.2.3.4"}},
		dryRun: true,
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("dry-run cleanup: %v", err)
	}
	if len(cf.deleteCalls) != 0 {
		t.Fatalf("dry-run must not delete, got %+v", cf.deleteCalls)
	}
}

func TestCleanupAppDryRunIsIdempotent(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"
	cf := &cleanupFakeCloudflare{rules: map[string]string{
		"5.6.7.8": "delete-rule",
	}}
	app := &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf:     cf,
		cs:     &cleanupFakeCrowdSec{activeBans: nil},
		dryRun: true,
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("first dry-run cleanup: %v", err)
	}
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("second dry-run cleanup: %v", err)
	}
	if len(cf.deleteCalls) != 0 {
		t.Fatalf("dry-run must remain mutation-free, got %+v", cf.deleteCalls)
	}
}

func TestCleanupPlanSeparatesKeptAndStaleRules(t *testing.T) {
	plan := buildCleanupPlan(map[string]bool{
		"1.2.3.4": true,
	}, map[string]string{
		"1.2.3.4": "keep-rule",
		"5.6.7.8": "delete-rule",
	})
	if len(plan.kept) != 1 || len(plan.stale) != 1 {
		t.Fatalf("unexpected cleanup plan: kept=%+v stale=%+v", plan.kept, plan.stale)
	}
	if plan.stale[0].Reason != "not in active CrowdSec bans" {
		t.Fatalf("unexpected stale reason: %+v", plan.stale[0])
	}
}

func TestCleanupAppIdempotentAcrossRunsOnCleanState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"
	cf := &cleanupFakeCloudflare{rules: map[string]string{
		"5.6.7.8": "delete-rule",
	}}
	app := &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf:     cf,
		cs:     &cleanupFakeCrowdSec{activeBans: nil},
	}

	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("first cleanup: %v", err)
	}
	if err := app.Run(context.Background()); err != nil {
		t.Fatalf("second cleanup on clean state: %v", err)
	}
	if len(cf.deleteCalls) != 1 {
		t.Fatalf("expected only one delete across idempotent runs, got %+v", cf.deleteCalls)
	}
}

func TestCleanupAppDetectsListFailureFailClosed(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"
	app := &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf: &cleanupFakeCloudflare{
			listErr: errors.New("cloudflare list failed"),
		},
		cs:     &cleanupFakeCrowdSec{activeBans: nil},
		dryRun: true,
	}

	if err := app.Run(context.Background()); err == nil {
		t.Fatal("expected cleanup dry-run to fail closed on list error")
	}
}

func TestCleanupAppStopsBetweenDeletesWhenContextIsCanceled(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := config.DefaultConfig()
	cfg.Cloudflare.ZoneID = "zone-123"
	ctx, cancel := context.WithCancel(context.Background())
	cf := &cleanupFakeCloudflare{rules: map[string]string{
		"5.6.7.8":    "delete-rule-1",
		"9.10.11.12": "delete-rule-2",
	}}
	cf.onDelete = cancel
	app := &CleanupApp{
		logger: logger,
		cfg:    cfg,
		cf:     cf,
		cs:     &cleanupFakeCrowdSec{activeBans: nil},
	}

	if err := app.Run(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
	if len(cf.deleteCalls) != 1 {
		t.Fatalf("expected cleanup to stop before second delete after cancellation, got %+v", cf.deleteCalls)
	}
}

func TestCleanupAppFailsClosedOnInvalidConfigViaLoader(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	t.Setenv("CF_ZONE_ID", "")
	_, err := config.Load("")
	if err == nil {
		t.Fatal("expected config loader to fail closed without token/zone")
	}
}
