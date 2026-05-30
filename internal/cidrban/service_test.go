package cidrban_test

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cidrban"
)

// ── Fakes ─────────────────────────────────────────────────────────────────────

type fakeBanSource struct {
	bans []cidrban.Ban
}

func (f *fakeBanSource) ListRecentBans(_ context.Context) ([]cidrban.Ban, error) {
	return f.bans, nil
}

type fakeCFBanner struct {
	mu    sync.Mutex
	added []string // CIDR strings passed to AddIPAccessRule
}

func (f *fakeCFBanner) AddIPAccessRule(_ context.Context, _, cidr, _, target string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.added = append(f.added, cidr+"/"+target)
	return "fake-rule-id", nil
}

type fakeCFRuleGetter struct {
	rules map[string]string
}

func (f *fakeCFRuleGetter) ListIPAccessRulesByTag(_ context.Context, _, _ string) (map[string]string, error) {
	if f.rules == nil {
		return make(map[string]string), nil
	}
	return f.rules, nil
}

type fakeCFDeleter struct {
	mu      sync.Mutex
	deleted []string
}

func (f *fakeCFDeleter) DeleteIPAccessRule(_ context.Context, _, ruleID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deleted = append(f.deleted, ruleID)
	return nil
}

type fakeCSRange struct {
	mu     sync.Mutex
	ranges []string
}

func (f *fakeCSRange) AddRangeDecision(_ context.Context, cidr, _, _ string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ranges = append(f.ranges, cidr)
	return nil
}

// ── Tests ─────────────────────────────────────────────────────────────────────

// TestCIDREscalation_TwoIPsSameSubnet verifies that two distinct IPs from the
// same /24 subnet trigger both a Cloudflare /24 ban and a CrowdSec range decision.
// This mirrors Python's sync_cidr_bans() threshold logic (CIDR_THRESHOLD = 2).
func TestCIDREscalation_TwoIPsSameSubnet(t *testing.T) {
	dir := t.TempDir()
	banner := &fakeCFBanner{}
	ranger := &fakeCSRange{}

	svc := cidrban.NewService(cidrban.Config{
		StateDir: dir,
		BanSource: &fakeBanSource{bans: []cidrban.Ban{
			{IP: "1.2.3.10", When: time.Now()},
			{IP: "1.2.3.20", When: time.Now()},
		}},
		CFBanner:      banner,
		CFRuleGetter:  &fakeCFRuleGetter{},
		CFDeleter:     &fakeCFDeleter{},
		CSRangeBanner: ranger,
		ZoneID:        "zone-test",
	})

	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	// Both IPs are in 1.2.3.0/24 → expect exactly one /24 ban added to CF.
	banner.mu.Lock()
	defer banner.mu.Unlock()
	if len(banner.added) != 1 {
		t.Fatalf("want 1 CF rule added (the /24), got %d: %v", len(banner.added), banner.added)
	}
	// Verify the /24 address and target type.
	const wantCIDR = "1.2.3.0/24/ip_range"
	if banner.added[0] != wantCIDR {
		t.Errorf("want CF rule %q, got %q", wantCIDR, banner.added[0])
	}

	// Verify CrowdSec range decision was also issued.
	ranger.mu.Lock()
	defer ranger.mu.Unlock()
	if len(ranger.ranges) != 1 || ranger.ranges[0] != "1.2.3.0/24" {
		t.Errorf("want 1 CS range decision for 1.2.3.0/24, got %v", ranger.ranges)
	}
}

// TestCIDREscalation_OneIPDoesNotTrigger verifies that a single IP from a /24
// does not trigger a ban (threshold = 2, mirrors Python's CIDR_THRESHOLD).
func TestCIDREscalation_OneIPDoesNotTrigger(t *testing.T) {
	dir := t.TempDir()
	banner := &fakeCFBanner{}

	svc := cidrban.NewService(cidrban.Config{
		StateDir: dir,
		BanSource: &fakeBanSource{bans: []cidrban.Ban{
			{IP: "1.2.3.10", When: time.Now()},
		}},
		CFBanner:     banner,
		CFRuleGetter: &fakeCFRuleGetter{},
		CFDeleter:    &fakeCFDeleter{},
		ZoneID:       "zone-test",
	})

	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	banner.mu.Lock()
	defer banner.mu.Unlock()
	if len(banner.added) != 0 {
		t.Errorf("want 0 CF rules for single IP, got %d: %v", len(banner.added), banner.added)
	}
}

// TestCIDREscalation_IPv6Excluded verifies IPv6 addresses are not grouped into /24
// subnets (mirrors Python's get_cidr24() which returns None for IPv6).
func TestCIDREscalation_IPv6Excluded(t *testing.T) {
	dir := t.TempDir()
	banner := &fakeCFBanner{}

	svc := cidrban.NewService(cidrban.Config{
		StateDir: dir,
		BanSource: &fakeBanSource{bans: []cidrban.Ban{
			{IP: "2001:db8::1", When: time.Now()},
			{IP: "2001:db8::2", When: time.Now()},
		}},
		CFBanner:     banner,
		CFRuleGetter: &fakeCFRuleGetter{},
		CFDeleter:    &fakeCFDeleter{},
		ZoneID:       "zone-test",
	})

	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	banner.mu.Lock()
	defer banner.mu.Unlock()
	if len(banner.added) != 0 {
		t.Errorf("want 0 CF rules for IPv6 (excluded by design), got %d", len(banner.added))
	}
}

// TestCIDREscalation_AlreadyBannedCIDRNotDuplicated verifies that a /24 already
// present in CF (returned by CFRuleGetter) does not trigger a duplicate rule add.
func TestCIDREscalation_AlreadyBannedCIDRNotDuplicated(t *testing.T) {
	dir := t.TempDir()
	banner := &fakeCFBanner{}

	svc := cidrban.NewService(cidrban.Config{
		StateDir: dir,
		BanSource: &fakeBanSource{bans: []cidrban.Ban{
			{IP: "1.2.3.10", When: time.Now()},
			{IP: "1.2.3.20", When: time.Now()},
		}},
		CFBanner: banner,
		CFRuleGetter: &fakeCFRuleGetter{rules: map[string]string{
			"1.2.3.0/24": "existing-rule-id",
		}},
		CFDeleter: &fakeCFDeleter{},
		ZoneID:    "zone-test",
	})

	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	banner.mu.Lock()
	defer banner.mu.Unlock()
	if len(banner.added) != 0 {
		t.Errorf("want 0 new CF rules when /24 already in CF, got %d: %v", len(banner.added), banner.added)
	}
}

// TestCIDREscalation_ExpiredBanCleaned verifies that a /24 recorded in state
// and older than 24h has its CF rule deleted on the next cycle.
//
// Note: the service (mirroring Python's sync_cidr_bans) returns early when
// len(bans)==0 — expiry runs only when there are *also* current bans to process.
// The test therefore includes a ban from a *different* /24 so the main loop runs,
// allowing the expiry cleanup to execute for the stale /24.
func TestCIDREscalation_ExpiredBanCleaned(t *testing.T) {
	dir := t.TempDir()
	deleter := &fakeCFDeleter{}
	banner := &fakeCFBanner{}

	// Write a stale state file (banned > 24h ago) for 1.2.3.0/24.
	stateJSON := `{"1.2.3.0/24":{"banned_at":"2020-01-01T00:00:00Z","ip_count":2}}`
	if err := os.WriteFile(dir+"/cidr-banned.json", []byte(stateJSON), 0644); err != nil {
		t.Fatal(err)
	}

	svc := cidrban.NewService(cidrban.Config{
		StateDir: dir,
		// A ban from a *different* /24 (9.9.9.0/24) so the service doesn't
		// return early — only one IP so no new /24 ban is created.
		BanSource: &fakeBanSource{bans: []cidrban.Ban{
			{IP: "9.9.9.1", When: time.Now()},
		}},
		CFBanner: banner,
		CFRuleGetter: &fakeCFRuleGetter{rules: map[string]string{
			"1.2.3.0/24": "old-rule-id",
		}},
		CFDeleter: deleter,
		ZoneID:    "zone-test",
	})

	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("Run error: %v", err)
	}

	deleter.mu.Lock()
	defer deleter.mu.Unlock()
	if len(deleter.deleted) != 1 || deleter.deleted[0] != "old-rule-id" {
		t.Errorf("want expired CF rule 'old-rule-id' deleted, got %v", deleter.deleted)
	}
	// Verify no new ban was added (9.9.9.0/24 has only 1 IP — below threshold).
	banner.mu.Lock()
	defer banner.mu.Unlock()
	if len(banner.added) != 0 {
		t.Errorf("want no new CF rule for single-IP /24, got %v", banner.added)
	}
}

// TestCIDREscalation_NilBanSourceIsNoop verifies that a nil BanSource makes the
// service a no-op (safe default, prevents panic).
func TestCIDREscalation_NilBanSourceIsNoop(t *testing.T) {
	svc := cidrban.NewService(cidrban.Config{
		StateDir:  t.TempDir(),
		BanSource: nil, // intentionally nil
	})
	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("expected no error with nil BanSource, got: %v", err)
	}
}
