package banlifecycle

import (
	"testing"
	"time"
)

// TestDefaultDurationPolicy_Tiers confirms the mission-mandated default
// tiers: 1st ban -> 1h, 2nd -> 6h, 3rd+ -> 24h.
func TestDefaultDurationPolicy_Tiers(t *testing.T) {
	p := DefaultDurationPolicy()

	cases := []struct {
		level int
		want  time.Duration
	}{
		{level: 0, want: 1 * time.Hour},  // <=1 treated as first
		{level: 1, want: 1 * time.Hour},  // first ban
		{level: 2, want: 6 * time.Hour},  // second ban
		{level: 3, want: 24 * time.Hour}, // third+
		{level: 4, want: 24 * time.Hour}, // third+ (no further escalation)
		{level: 100, want: 24 * time.Hour},
	}
	for _, c := range cases {
		got := p.DurationFor(c.level)
		if got != c.want {
			t.Errorf("DurationFor(%d) = %v, want %v", c.level, got, c.want)
		}
	}
}

// TestDefaultDurationPolicy_NeverExceeds24h confirms the hard cap holds
// across the whole default tier range, and that the policy never
// reintroduces the old 168h (1 week) tier.
func TestDefaultDurationPolicy_NeverExceeds24h(t *testing.T) {
	p := DefaultDurationPolicy()
	for level := -5; level <= 50; level++ {
		got := p.DurationFor(level)
		if got > MaxBanDuration {
			t.Fatalf("DurationFor(%d) = %v, exceeds MaxBanDuration (%v)", level, got, MaxBanDuration)
		}
		if got == 168*time.Hour {
			t.Fatalf("DurationFor(%d) returned the old 168h (1 week) tier, which must no longer exist", level)
		}
	}
}

// TestDurationFor_ClampsMisconfiguredPolicy confirms that even an
// operator-overridden DurationPolicy whose values exceed 24h is clamped by
// DurationFor, so the "never exceed 24h" guarantee holds regardless of how
// the policy was constructed.
func TestDurationFor_ClampsMisconfiguredPolicy(t *testing.T) {
	p := DurationPolicy{
		First:     2 * time.Hour,
		Second:    48 * time.Hour,  // intentionally misconfigured, above cap
		ThirdPlus: 168 * time.Hour, // intentionally misconfigured, above cap
	}

	if got := p.DurationFor(1); got != 2*time.Hour {
		t.Errorf("DurationFor(1) = %v, want 2h (below cap, unclamped)", got)
	}
	if got := p.DurationFor(2); got != MaxBanDuration {
		t.Errorf("DurationFor(2) = %v, want clamped to %v", got, MaxBanDuration)
	}
	if got := p.DurationFor(3); got != MaxBanDuration {
		t.Errorf("DurationFor(3) = %v, want clamped to %v", got, MaxBanDuration)
	}
}

// TestDurationFor_MonotonicallyIncreasing confirms the chosen default curve
// (1h -> 6h -> 24h) is monotonically non-decreasing across recidive levels,
// as the operator required ("escalade 1H jusqu'à 24H maximum").
func TestDurationFor_MonotonicallyIncreasing(t *testing.T) {
	p := DefaultDurationPolicy()
	prev := time.Duration(0)
	for level := 1; level <= 5; level++ {
		got := p.DurationFor(level)
		if got < prev {
			t.Fatalf("DurationFor(%d) = %v is less than previous level's %v; escalation must be monotonically non-decreasing", level, got, prev)
		}
		prev = got
	}
}
