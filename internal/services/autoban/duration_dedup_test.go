package autoban

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/trust"
)

// newTestEvaluator constructs an Evaluator with a controllable clock, for
// white-box tests that need to simulate time passing past a specific ban's
// TTL without sleeping in real time. liveMode is always true here: these
// tests exercise the guard/dedup mechanics, not shadow-mode behaviour.
func newTestEvaluator(clock *fakeClock) *Evaluator {
	ev := NewEvaluator(Config{LiveMode: true}, trust.DefaultRegistry(), nil, nil)
	ev.now = clock.Now
	return ev
}

type fakeClock struct {
	t time.Time
}

func (c *fakeClock) Now() time.Time { return c.t }

func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// TestBanDedup_PerIPTTL_FirstTierExpiresBeforeFixedTTL reproduces the exact
// bug scenario from the audit: a 1h first-tier ban recorded with its real
// (short) duration must release the dedup guard once THAT duration elapses —
// not the old fixed 24h BanDedupTTL.
func TestBanDedup_PerIPTTL_FirstTierExpiresBeforeFixedTTL(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)}
	ev := newTestEvaluator(clock)
	const ip = "203.0.113.10"

	firstTierDuration := 1 * time.Hour
	ev.RecordBanWithDuration(ip, firstTierDuration)

	// Immediately after recording: still within the 1h window, must be
	// treated as already banned.
	if skip := ev.guardIP(ip, clock.Now()); skip != "already_banned" {
		t.Fatalf("immediately after RecordBanWithDuration: guardIP = %q, want already_banned", skip)
	}

	// Advance past the REAL 1h duration but still well within the old fixed
	// 24h BanDedupTTL. With the bug, this would still report already_banned
	// for the full 24h; with the fix, the guard must have released by now.
	clock.Advance(firstTierDuration + time.Second)

	if skip := ev.guardIP(ip, clock.Now()); skip == "already_banned" {
		t.Fatalf("2h after a 1h first-tier ban: guardIP still reports already_banned — dedup TTL did not track the real ban duration (the bug this test guards against)")
	}

	// New malicious activity resumes at hour 2 (well within burst-prune
	// lookback of "now") — feed enough events to cross BurstThreshold, the
	// same way a fresh malicious-event burst would in production.
	for i := 0; i < BurstThreshold+1; i++ {
		ev.RecordMalicious(MaliciousEvent{IP: ip, AbuseType: "scanner", Timestamp: clock.Now()})
	}

	decision := ev.EvaluateBurst(ip)
	if decision.SkipReason == "already_banned" {
		t.Fatalf("EvaluateBurst after real ban expiry: SkipReason = already_banned, want ShouldBan=true (decision=%+v)", decision)
	}
	if !decision.ShouldBan {
		t.Fatalf("EvaluateBurst after real ban expiry: expected ShouldBan=true, got %+v", decision)
	}
}

// TestBanDedup_PerIPTTL_ThirdTierStillBlocksForFull24h confirms a 3rd-tier
// (now capped at 24h) ban still correctly blocks re-evaluation for the FULL
// 24h, not less — the fix must not weaken the long-duration tier's guard.
func TestBanDedup_PerIPTTL_ThirdTierStillBlocksForFull24h(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)}
	ev := newTestEvaluator(clock)
	const ip = "203.0.113.20"

	thirdTierDuration := 24 * time.Hour // banlifecycle.MaxBanDuration / DefaultThirdPlusBanDuration
	ev.RecordBanWithDuration(ip, thirdTierDuration)

	// Just before the 24h mark: still guarded.
	clock.Advance(24*time.Hour - time.Second)
	if skip := ev.guardIP(ip, clock.Now()); skip != "already_banned" {
		t.Fatalf("23h59m59s after a 24h third-tier ban: guardIP = %q, want already_banned", skip)
	}

	// Just after the 24h mark: guard releases.
	clock.Advance(2 * time.Second)
	if skip := ev.guardIP(ip, clock.Now()); skip == "already_banned" {
		t.Fatalf("just after 24h elapsed: guardIP still reports already_banned, want released")
	}
}

// TestBanDedup_LegacyRecordBan_FallsBackTo24h confirms RecordBan (the
// no-duration-known legacy path) still guards for the fixed BanDedupTTL,
// preserving backward-compatible behaviour for callers that don't know a
// specific duration.
func TestBanDedup_LegacyRecordBan_FallsBackTo24h(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)}
	ev := newTestEvaluator(clock)
	const ip = "203.0.113.30"

	ev.RecordBan(ip)

	clock.Advance(BanDedupTTL - time.Second)
	if skip := ev.guardIP(ip, clock.Now()); skip != "already_banned" {
		t.Fatalf("just before legacy BanDedupTTL elapses: guardIP = %q, want already_banned", skip)
	}

	clock.Advance(2 * time.Second)
	if skip := ev.guardIP(ip, clock.Now()); skip == "already_banned" {
		t.Fatalf("just after legacy BanDedupTTL elapses: guardIP still reports already_banned, want released")
	}
}

// --- BanDedup unit tests (no Evaluator involved) ---

func TestBanDedup_PerIPTTL_DifferentIPsIndependentWindows(t *testing.T) {
	d := NewBanDedup(24 * time.Hour)
	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)

	d.MarkBanned("1.1.1.1", now, 1*time.Hour)
	d.MarkBanned("2.2.2.2", now, 24*time.Hour)

	later := now.Add(2 * time.Hour)
	if d.AlreadyBanned("1.1.1.1", later) {
		t.Errorf("1.1.1.1: expected guard released after its 1h TTL elapsed")
	}
	if !d.AlreadyBanned("2.2.2.2", later) {
		t.Errorf("2.2.2.2: expected guard still held within its 24h TTL")
	}
}

func TestBanDedup_MarkBannedDefaultTTL_UsesConfiguredDefault(t *testing.T) {
	d := NewBanDedup(24 * time.Hour)
	now := time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)

	d.MarkBannedDefaultTTL("3.3.3.3", now)

	if !d.AlreadyBanned("3.3.3.3", now.Add(23*time.Hour)) {
		t.Errorf("expected default TTL (24h) guard to still hold at +23h")
	}
	if d.AlreadyBanned("3.3.3.3", now.Add(25*time.Hour)) {
		t.Errorf("expected default TTL (24h) guard to have released at +25h")
	}
}

func TestBanDedup_ZeroOrNegativeTTL_RecordBanWithDurationFallsBack(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 6, 22, 0, 0, 0, 0, time.UTC)}
	ev := newTestEvaluator(clock)
	const ip = "203.0.113.40"

	// ttl <= 0 must not leave the IP unguarded; it must fall back to the
	// fixed legacy TTL rather than guessing short.
	ev.RecordBanWithDuration(ip, 0)

	clock.Advance(BanDedupTTL - time.Second)
	if skip := ev.guardIP(ip, clock.Now()); skip != "already_banned" {
		t.Fatalf("ttl<=0 fallback: expected guard to hold for the fixed legacy TTL, got %q", skip)
	}
}
