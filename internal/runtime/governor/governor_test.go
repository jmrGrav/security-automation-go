package governor_test

import (
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/scope"
)

func testScope() scope.RuntimeScope {
	return scope.RuntimeScope{
		Tenant:      "tenant-a",
		AccountID:   "acct-1",
		ZoneID:      "zone-1",
		Environment: "test",
	}
}

func newGov() *governor.ResourceGovernor {
	return governor.New(slog.New(slog.NewTextHandler(os.Stderr, nil)))
}

// TestAllow_NoLimitsRegistered verifies that Allow returns true when no limits exist.
func TestAllow_NoLimitsRegistered(t *testing.T) {
	g := newGov()
	s := testScope()
	// With no buckets registered, HierarchicalLimiter has all nil buckets, which should allow.
	if !g.Allow(s, "cloudflare", governor.ResourceRequest, 1) {
		t.Error("expected Allow to return true when no limits registered")
	}
}

// TestAllow_WithinBurst verifies that Allow permits requests within the burst budget.
func TestAllow_WithinBurst(t *testing.T) {
	g := newGov()
	g.RegisterProvider("cf", map[governor.ResourceType]governor.Limit{
		governor.ResourceRequest: {
			MaxBurst: 10,
			Rate:     5,
			Interval: time.Second,
		},
	})

	s := testScope()
	// First 10 requests should succeed (within burst).
	for i := 0; i < 10; i++ {
		if !g.Allow(s, "cf", governor.ResourceRequest, 1) {
			t.Fatalf("expected Allow to return true on iteration %d within burst", i)
		}
	}
}

// TestAllow_ExceedsBurst verifies that Allow denies after the burst is exhausted.
func TestAllow_ExceedsBurst(t *testing.T) {
	g := newGov()
	g.RegisterProvider("cf", map[governor.ResourceType]governor.Limit{
		governor.ResourceRequest: {
			MaxBurst: 3,
			Rate:     1,
			Interval: time.Hour, // very slow refill
		},
	})

	s := testScope()
	// Drain the bucket.
	for i := 0; i < 3; i++ {
		g.Allow(s, "cf", governor.ResourceRequest, 1)
	}
	// Next request should be denied.
	if g.Allow(s, "cf", governor.ResourceRequest, 1) {
		t.Error("expected Allow to return false after burst exhausted")
	}
}

// TestPressure_InRange verifies that Pressure returns a value in [0, 1].
func TestPressure_InRange(t *testing.T) {
	g := newGov()
	g.RegisterProvider("cf", map[governor.ResourceType]governor.Limit{
		governor.ResourceRequest: {
			MaxBurst: 100,
			Rate:     10,
			Interval: time.Second,
		},
	})

	p := g.Pressure("cf")
	if p < 0.0 || p > 1.0 {
		t.Errorf("expected Pressure in [0, 1], got %f", p)
	}
}

// TestPressure_UnknownProvider verifies that Pressure for an unknown provider is 0.
func TestPressure_UnknownProvider(t *testing.T) {
	g := newGov()
	p := g.Pressure("nonexistent")
	if p != 0.0 {
		t.Errorf("expected Pressure 0 for unknown provider, got %f", p)
	}
}

// TestPressure_IncreasesAfterUse verifies that Pressure rises after consuming tokens.
func TestPressure_IncreasesAfterUse(t *testing.T) {
	g := newGov()
	g.RegisterProvider("cf", map[governor.ResourceType]governor.Limit{
		governor.ResourceRequest: {
			MaxBurst: 10,
			Rate:     1,
			Interval: time.Hour,
		},
	})

	s := testScope()
	initial := g.Pressure("cf")

	// Consume some tokens.
	for i := 0; i < 5; i++ {
		g.Allow(s, "cf", governor.ResourceRequest, 1)
	}

	after := g.Pressure("cf")
	if after <= initial {
		t.Errorf("expected Pressure to increase after token consumption: initial=%f after=%f", initial, after)
	}
}
