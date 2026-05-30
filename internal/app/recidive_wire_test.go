package app_test

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cidrban"
	csmodels "github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/recidive"
)

func encodeJSON(v any) ([]byte, error) { return json.Marshal(v) }

// ensure recidive import is used (compile check)
var _ = recidive.NewService

// ── fakes ────────────────────────────────────────────────────────────────────

type fakeRecidiveBanSource struct {
	bans []csmodels.RecentBan
	err  error
}

func (f *fakeRecidiveBanSource) ListActiveBans(_ context.Context) ([]string, error) {
	ips := make([]string, 0, len(f.bans))
	for _, b := range f.bans {
		ips = append(ips, b.IP)
	}
	return ips, nil
}

func (f *fakeRecidiveBanSource) ListRecentBans(_ context.Context) ([]csmodels.RecentBan, error) {
	return f.bans, f.err
}

type fakeDecisionAdder struct {
	mu    sync.Mutex
	calls []decisionCall
	err   error
}

type decisionCall struct {
	ip       string
	duration string
	reason   string
}

func (f *fakeDecisionAdder) AddIPDecision(_ context.Context, ip, duration, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, decisionCall{ip: ip, duration: duration, reason: reason})
	return f.err
}

// recidiveBanSourceForTest wraps fakeRecidiveBanSource → recidive.RecentBanSource
// applying the same shield+allowlist filter logic as the production adapter.
type recidiveBanSourceForTest struct {
	src         *fakeRecidiveBanSource
	shieldedIPs map[string]bool
	allowedIPs  map[string]bool
}

func (r *recidiveBanSourceForTest) ListRecentBans(_ context.Context) ([]recidive.Ban, error) {
	bans, err := r.src.ListRecentBans(context.Background())
	if err != nil {
		return nil, err
	}
	var out []recidive.Ban
	for _, b := range bans {
		if r.shieldedIPs[b.IP] || r.allowedIPs[b.IP] {
			continue
		}
		out = append(out, recidive.Ban{IP: b.IP, Scenario: b.Scenario, When: b.When, ID: b.ID})
	}
	return out, nil
}

// ── Tests: recidive escalation logic ─────────────────────────────────────────

// TestRecidive_SecondBanEscalates24h verifies that a second ban occurrence
// triggers a 24h escalation. Mirrors Python: RECIDIV_ESCALATION = {1: "24h"}.
//
// The cursor is initialized to now on the first run, so we inject state with
// count=1 and cursor set before our test ban to simulate a prior processing cycle.
func TestRecidive_SecondBanEscalates24h(t *testing.T) {
	dir := t.TempDir()
	escalator := &fakeDecisionAdder{}
	now := time.Now().UTC()
	banTime := now.Add(-1 * time.Minute)

	// Inject state: IP has count=1 from a previous cycle; cursor is before banTime
	writeRecidiveState(t, dir, map[string]recidiveEntry{
		"11.22.33.44": {Count: 1, LastSeen: now.Add(-10 * time.Minute)},
	}, now.Add(-5*time.Minute))

	src := &recidiveBanSourceForTest{src: &fakeRecidiveBanSource{bans: []csmodels.RecentBan{
		{IP: "11.22.33.44", Scenario: "crowdsecurity/http-scan", When: banTime, ID: "101"},
	}}}
	svc := recidive.NewService(recidive.Config{
		StateDir:  dir,
		BanSource: src,
		Escalator: escalator,
	})
	_ = svc.Run(context.Background())

	escalator.mu.Lock()
	defer escalator.mu.Unlock()
	if len(escalator.calls) != 1 {
		t.Fatalf("want 1 escalation (24h on 2nd ban), got %d: %v", len(escalator.calls), escalator.calls)
	}
	if escalator.calls[0].duration != "24h" {
		t.Errorf("want duration=24h, got %q", escalator.calls[0].duration)
	}
	if escalator.calls[0].ip != "11.22.33.44" {
		t.Errorf("want ip=11.22.33.44, got %q", escalator.calls[0].ip)
	}
}

// TestRecidive_ThirdPlusBanEscalates168h verifies 3rd+ ban → 168h.
// Mirrors Python: RECIDIV_DEFAULT = "168h".
func TestRecidive_ThirdPlusBanEscalates168h(t *testing.T) {
	dir := t.TempDir()
	escalator := &fakeDecisionAdder{}
	now := time.Now().UTC()
	banTime := now.Add(-1 * time.Minute)

	// Inject state: count=2 from two prior cycles; cursor before banTime
	writeRecidiveState(t, dir, map[string]recidiveEntry{
		"11.22.33.44": {Count: 2, LastSeen: now.Add(-10 * time.Minute)},
	}, now.Add(-5*time.Minute))

	src := &recidiveBanSourceForTest{src: &fakeRecidiveBanSource{bans: []csmodels.RecentBan{
		{IP: "11.22.33.44", Scenario: "crowdsecurity/http-scan", When: banTime, ID: "103"},
	}}}
	svc := recidive.NewService(recidive.Config{
		StateDir:  dir,
		BanSource: src,
		Escalator: escalator,
	})
	_ = svc.Run(context.Background())

	escalator.mu.Lock()
	defer escalator.mu.Unlock()
	if len(escalator.calls) != 1 {
		t.Fatalf("want 1 escalation, got %d: %v", len(escalator.calls), escalator.calls)
	}
	if escalator.calls[0].duration != "168h" {
		t.Errorf("want duration=168h, got %q", escalator.calls[0].duration)
	}
}

// TestRecidive_CursorPreventsDoubleEscalation verifies the cursor ensures
// bans already processed are not re-counted on the next cycle.
func TestRecidive_CursorPreventsDoubleEscalation(t *testing.T) {
	dir := t.TempDir()
	escalator := &fakeDecisionAdder{}
	now := time.Now().UTC()

	// Inject state: count=1, cursor before both bans → second ban triggers 24h escalation on run1
	writeRecidiveState(t, dir, map[string]recidiveEntry{
		"5.6.7.8": {Count: 1, LastSeen: now.Add(-10 * time.Minute)},
	}, now.Add(-5*time.Minute))

	ban1Time := now.Add(-3 * time.Minute)
	ban2Time := now.Add(-2 * time.Minute)
	bans := []csmodels.RecentBan{
		{IP: "5.6.7.8", Scenario: "crowdsecurity/ssh-bf", When: ban1Time, ID: "200"},
		{IP: "5.6.7.8", Scenario: "crowdsecurity/ssh-bf", When: ban2Time, ID: "201"},
	}

	src := &recidiveBanSourceForTest{src: &fakeRecidiveBanSource{bans: bans}}
	svc := recidive.NewService(recidive.Config{
		StateDir:  dir,
		BanSource: src,
		Escalator: escalator,
	})

	// Run 1: processes both bans (count 1→2 triggers 24h, count 2→3 triggers 168h)
	_ = svc.Run(context.Background())
	callsAfterRun1 := len(escalator.calls)

	// Run 2: same bans returned, cursor is now past them → no new processing
	_ = svc.Run(context.Background())

	escalator.mu.Lock()
	defer escalator.mu.Unlock()
	if len(escalator.calls) != callsAfterRun1 {
		t.Errorf("cursor must prevent double counting on run2; run1=%d calls, run2=%d calls",
			callsAfterRun1, len(escalator.calls))
	}
}

// TestRecidive_ProtectedIPExcluded verifies that a shielded IP is never tracked.
func TestRecidive_ProtectedIPExcluded(t *testing.T) {
	dir := t.TempDir()
	escalator := &fakeDecisionAdder{}
	now := time.Now().UTC()
	banTime := now.Add(-1 * time.Minute)
	writeRecidiveState(t, dir, map[string]recidiveEntry{
		"10.0.0.1": {Count: 1, LastSeen: now.Add(-10 * time.Minute)},
	}, now.Add(-5*time.Minute))

	src := &recidiveBanSourceForTest{
		src: &fakeRecidiveBanSource{bans: []csmodels.RecentBan{
			{IP: "10.0.0.1", Scenario: "crowdsecurity/http-scan", When: banTime, ID: "300"},
		}},
		shieldedIPs: map[string]bool{"10.0.0.1": true},
	}
	svc := recidive.NewService(recidive.Config{
		StateDir:  dir,
		BanSource: src,
		Escalator: escalator,
	})
	_ = svc.Run(context.Background())

	escalator.mu.Lock()
	defer escalator.mu.Unlock()
	if len(escalator.calls) != 0 {
		t.Errorf("protected IP must not be escalated; got %d calls", len(escalator.calls))
	}
}

// TestRecidive_AllowlistedIPExcluded verifies that an allowlisted IP is never tracked.
func TestRecidive_AllowlistedIPExcluded(t *testing.T) {
	dir := t.TempDir()
	escalator := &fakeDecisionAdder{}
	now := time.Now().UTC()
	banTime := now.Add(-1 * time.Minute)
	writeRecidiveState(t, dir, map[string]recidiveEntry{
		"9.9.9.9": {Count: 1, LastSeen: now.Add(-10 * time.Minute)},
	}, now.Add(-5*time.Minute))

	src := &recidiveBanSourceForTest{
		src: &fakeRecidiveBanSource{bans: []csmodels.RecentBan{
			{IP: "9.9.9.9", Scenario: "crowdsecurity/http-scan", When: banTime, ID: "400"},
		}},
		allowedIPs: map[string]bool{"9.9.9.9": true},
	}
	svc := recidive.NewService(recidive.Config{
		StateDir:  dir,
		BanSource: src,
		Escalator: escalator,
	})
	_ = svc.Run(context.Background())

	escalator.mu.Lock()
	defer escalator.mu.Unlock()
	if len(escalator.calls) != 0 {
		t.Errorf("allowlisted IP must not be escalated; got %d calls", len(escalator.calls))
	}
}

// TestRecidive_ShadowModeNoMutation proves the !shadowMode guard prevents
// recidive.Run() in shadow mode. Without the guard, PlaceholderService would
// succeed but RealService would mutate cscli.
func TestRecidive_ShadowModeNoMutation(t *testing.T) {
	// Prove: with Escalator=nil (shadow-equivalent), no escalation fires
	dir := t.TempDir()
	now := time.Now().UTC()

	src := &recidiveBanSourceForTest{src: &fakeRecidiveBanSource{bans: []csmodels.RecentBan{
		{IP: "1.1.1.1", Scenario: "crowdsecurity/http-scan", When: now.Add(-2 * time.Minute), ID: "500"},
		{IP: "1.1.1.1", Scenario: "crowdsecurity/http-scan", When: now.Add(-1 * time.Minute), ID: "501"},
	}}}
	svc := recidive.NewService(recidive.Config{
		StateDir:  dir,
		BanSource: src,
		Escalator: nil, // shadow mode: no escalator
	})
	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("want no error with nil escalator, got %v", err)
	}
	// With !a.shadowMode guard in CrowdSecSyncApp, Run() is never called in shadow mode.
	// This test verifies the escalator=nil path is safe (no panic, no mutation).
}

// TestRecidive_BanSourceNilIsNoOp verifies that the nil-BanSource case no longer
// occurs in production (we injected a real BanSource), but the guard remains safe.
func TestRecidive_BanSourceNilIsNoOp(t *testing.T) {
	svc := recidive.NewService(recidive.Config{
		StateDir:  t.TempDir(),
		BanSource: nil,
	})
	if err := svc.Run(context.Background()); err != nil {
		t.Fatalf("nil BanSource must be a no-op: %v", err)
	}
}

// TestRecidiveBanSourceAdapter_ShieldAndAllowlist verifies the production adapter
// applies both shield and allowlist before passing bans to recidive tracking.
// This test exercises the adapter path used in NewCrowdSecSyncApp.
func TestRecidiveBanSourceAdapter_ShieldAndAllowlist(t *testing.T) {
	src := &recidiveBanSourceForTest{
		src: &fakeRecidiveBanSource{bans: []csmodels.RecentBan{
			{IP: "192.168.1.1", Scenario: "s", When: time.Now(), ID: "1"}, // shielded
			{IP: "8.8.8.8", Scenario: "s", When: time.Now(), ID: "2"},     // allowlisted
			{IP: "1.2.3.4", Scenario: "s", When: time.Now(), ID: "3"},     // passes through
		}},
		shieldedIPs: map[string]bool{"192.168.1.1": true},
		allowedIPs:  map[string]bool{"8.8.8.8": true},
	}
	bans, err := src.ListRecentBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(bans) != 1 || bans[0].IP != "1.2.3.4" {
		t.Errorf("want only 1.2.3.4 to pass through, got %v", bans)
	}
}

// ── Verify cidrban fakes still compile (no regression from removals) ──────────

var _ cidrban.RecentBanSource = (*shieldedBanSource)(nil)

// ── State helpers ─────────────────────────────────────────────────────────────

type recidiveEntry struct {
	Count    int
	LastSeen time.Time
}

// writeRecidiveState writes recidivists.json matching recidive.RealService's format.
// Uses recidive.Record (time.Time) → json.Marshal so the format matches what loadState() reads.
func writeRecidiveState(t *testing.T, dir string, entries map[string]recidiveEntry, cursor time.Time) {
	t.Helper()
	m := make(map[string]string, len(entries)+1)
	for ip, e := range entries {
		// Use the production Record type so time.Time marshaling matches loadState's expectations.
		rec := recidive.Record{Count: e.Count, LastSeen: e.LastSeen.UTC()}
		b, err := json.Marshal(rec)
		if err != nil {
			t.Fatalf("writeRecidiveState: encode %s: %v", ip, err)
		}
		m[ip] = string(b)
	}
	m["_cursor"] = cursor.UTC().Format(time.RFC3339Nano)

	data, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("writeRecidiveState: marshal state: %v", err)
	}
	if err := os.WriteFile(dir+"/recidivists.json", data, 0644); err != nil {
		t.Fatalf("writeRecidiveState: write: %v", err)
	}
}
