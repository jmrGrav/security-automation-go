package reporting

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/abuseformat"
	"github.com/jm/security-automation-go/internal/security/classifier"
)

func TestDecisionGateDeduplicatesRecentFingerprint(t *testing.T) {
	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	gate := newDecisionGate(time.Hour, func() time.Time { return base })
	req := mustCloudflareRequest(t, base, "8.8.8.8", "/search?q=union+select+1")
	cls := classifier.Classification{Categories: []string{"Bad Web Bot"}, Confidence: 0.9}

	if gate.isDuplicate(req, cls) {
		t.Fatal("first observation must not be duplicate")
	}
	if !gate.isDuplicate(req, cls) {
		t.Fatal("second observation within TTL must be duplicate")
	}

	gate.setClock(func() time.Time { return base.Add(2 * time.Hour) })
	if gate.isDuplicate(req, cls) {
		t.Fatal("expired fingerprint must be evicted")
	}
}

func TestDecisionGateSerializesIPLocks(t *testing.T) {
	gate := newDecisionGate(time.Minute, func() time.Time { return time.Now().UTC() })
	release := gate.lockIP("8.8.8.8")

	locked := make(chan struct{}, 1)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		nextRelease := gate.lockIP("8.8.8.8")
		locked <- struct{}{}
		nextRelease()
	}()

	select {
	case <-locked:
		t.Fatal("concurrent lock should block until first release")
	case <-time.After(100 * time.Millisecond):
	}

	release()
	wg.Wait()
	select {
	case <-locked:
	default:
		t.Fatal("concurrent lock must eventually acquire after release")
	}
}

func TestDecisionGateSetClockPropagatesClock(t *testing.T) {
	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	gate := newDecisionGate(time.Hour, func() time.Time { return base })
	req := mustCloudflareRequest(t, base, "8.8.4.4", "/search?q=union+select+1")
	cls := classifier.Classification{Categories: []string{"Bad Web Bot"}, Confidence: 0.9}

	if gate.isDuplicate(req, cls) {
		t.Fatal("first observation must not be duplicate")
	}

	gate.setClock(func() time.Time { return base.Add(2 * time.Hour) })
	if gate.isDuplicate(req, cls) {
		t.Fatal("updated clock should expire prior fingerprint")
	}
}

func TestDecisionGatePrunesStaleIPLocks(t *testing.T) {
	base := time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)
	gate := newDecisionGate(time.Hour, func() time.Time { return base })

	for i := 0; i < 20; i++ {
		ip := fmt.Sprintf("192.0.2.%d", i)
		release := gate.lockIP(ip)
		release()
	}
	if got := len(gate.ipLocks); got != 20 {
		t.Fatalf("expected 20 tracked IP locks, got %d", got)
	}

	gate.setClock(func() time.Time { return base.Add(2 * time.Hour) })
	release := gate.lockIP("192.0.2.250")
	release()

	if got := len(gate.ipLocks); got > 1 {
		t.Fatalf("expected stale IP locks to be pruned, got %d", got)
	}
}

func mustCloudflareRequest(t *testing.T, ts time.Time, ip string, uri string) Request {
	t.Helper()
	event := classifier.Event{
		IP:        ip,
		URI:       uri,
		UserAgent: "sqlmap",
		Timestamp: ts,
		Hits:      10,
		WindowSec: 300,
		RuleID:    "r1",
		Action:    "block",
		Source:    "cloudflare_waf",
		Hostname:  "arleo.eu",
	}
	return Request{Source: abuseformat.SourceCloudflareWAF, Event: event}
}
