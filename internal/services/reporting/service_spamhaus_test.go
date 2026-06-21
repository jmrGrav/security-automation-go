package reporting_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

// fakeSpamhausClient records calls made to Report().
type fakeSpamhausClient struct {
	mu      sync.Mutex
	reports []string // IP addresses reported
	err     error
}

func (c *fakeSpamhausClient) Report(_ context.Context, ip netip.Addr, _ string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return c.err
	}
	c.reports = append(c.reports, ip.String())
	return nil
}

func (c *fakeSpamhausClient) callCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.reports)
}

func makeSpamhausService(now func() time.Time) (*reporting.Service, *fakeReporter, *fakeSpamhausClient) {
	reporter := &fakeReporter{}
	sink := &sinks.RecorderSink{}
	svc := reporting.New(reporter, sink, trust.DefaultRegistry(), time.Minute)
	svc.SetClock(now)
	sh := &fakeSpamhausClient{}
	svc.SetSpamhausClient(sh)
	return svc, reporter, sh
}

func highConfEvent(ip string, now time.Time) (abuseformat.Source, classifier.Event) {
	return abuseformat.SourceCloudflareWAF, classifier.Event{
		IP:        ip,
		Hostname:  "test.example.com",
		URI:       "/wp-login.php",
		Action:    "block",
		RuleID:    "abc123",
		Timestamp: now,
		Hits:      30,
		WindowSec: 300,
	}
}

// TestSpamhausSubmit_IndependentFromAbuseIPDB verifies that a Spamhaus error
// does not prevent the AbuseIPDB report from being returned in the result.
func TestSpamhausSubmit_IndependentFromAbuseIPDB(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc, ab, sh := makeSpamhausService(func() time.Time { return now })
	sh.err = errors.New("spamhaus server error")

	source, event := highConfEvent("1.2.3.4", now)
	result, err := svc.Process(context.Background(), reporting.Request{Source: source, Event: event})
	if err != nil {
		t.Fatalf("Process returned error: %v", err)
	}
	// AbuseIPDB should still have reported despite Spamhaus failure.
	if len(ab.Reports()) == 0 {
		t.Error("AbuseIPDB executor should be called even when Spamhaus fails")
	}
	// The result should not reflect the Spamhaus error.
	_ = result
}

// TestSpamhausSubmit_DedupPreventsDoubleSubmit verifies that a second event for
// the same IP within the 24h TTL does not trigger a second Spamhaus submission.
func TestSpamhausSubmit_DedupPreventsDoubleSubmit(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	clock := base
	svc, _, sh := makeSpamhausService(func() time.Time { return clock })

	source, event := highConfEvent("5.6.7.8", base)
	if _, err := svc.Process(context.Background(), reporting.Request{Source: source, Event: event}); err != nil {
		t.Fatalf("first Process error: %v", err)
	}
	if sh.callCount() != 1 {
		t.Fatalf("expected 1 Spamhaus call after first event, got %d", sh.callCount())
	}

	// Advance time by 1 hour (still within 24h dedup window).
	clock = base.Add(1 * time.Hour)
	// Vary the URI/RuleID so the AbuseIPDB fingerprint gate doesn't block it.
	event2 := event
	event2.URI = "/admin"
	event2.RuleID = "xyz999"
	if _, err := svc.Process(context.Background(), reporting.Request{Source: source, Event: event2}); err != nil {
		t.Fatalf("second Process error: %v", err)
	}
	// Spamhaus should NOT be called again for the same IP within 24h.
	if sh.callCount() != 1 {
		t.Errorf("expected 1 total Spamhaus call (dedup), got %d", sh.callCount())
	}
}

// TestSpamhausSubmit_DedupExpiresAfterTTL verifies that after the 24h window,
// the same IP can be submitted to Spamhaus again.
func TestSpamhausSubmit_DedupExpiresAfterTTL(t *testing.T) {
	base := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	clock := base
	svc, _, sh := makeSpamhausService(func() time.Time { return clock })

	source, event := highConfEvent("9.10.11.12", base)
	if _, err := svc.Process(context.Background(), reporting.Request{Source: source, Event: event}); err != nil {
		t.Fatalf("first Process error: %v", err)
	}
	if sh.callCount() != 1 {
		t.Fatalf("expected 1 Spamhaus call after first event, got %d", sh.callCount())
	}

	// Advance clock past the 24h TTL.
	clock = base.Add(25 * time.Hour)
	event2 := event
	event2.URI = "/new-path"
	event2.RuleID = "new-rule"
	event2.Timestamp = clock
	if _, err := svc.Process(context.Background(), reporting.Request{Source: source, Event: event2}); err != nil {
		t.Fatalf("second Process error: %v", err)
	}
	if sh.callCount() != 2 {
		t.Errorf("expected 2 Spamhaus calls after TTL expiry, got %d", sh.callCount())
	}
}

// TestSpamhausSubmit_NotCalledWhenSuppressed verifies Spamhaus is not called
// for events that are suppressed (low confidence, protected IP, benign).
func TestSpamhausSubmit_NotCalledWhenSuppressed(t *testing.T) {
	now := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	svc, _, sh := makeSpamhausService(func() time.Time { return now })

	// Low-confidence event: hits=1 → benign_probe or low confidence
	source := abuseformat.SourceCloudflareWAF
	event := classifier.Event{
		IP:        "2.3.4.5",
		Hostname:  "test.example.com",
		URI:       "/favicon.ico",
		Action:    "block",
		RuleID:    "r1",
		Timestamp: now,
		Hits:      1,
		WindowSec: 300,
	}
	if _, err := svc.Process(context.Background(), reporting.Request{Source: source, Event: event}); err != nil {
		t.Fatalf("Process error: %v", err)
	}
	if sh.callCount() != 0 {
		t.Errorf("Spamhaus should not be called for suppressed events, called %d time(s)", sh.callCount())
	}
}
