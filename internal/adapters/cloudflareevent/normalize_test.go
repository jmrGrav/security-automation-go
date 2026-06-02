package cloudflareevent_test

import (
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
)

func baseEvent() cloudflareevent.RawEvent {
	return cloudflareevent.RawEvent{
		IP:        "1.2.3.4",
		URI:       "/admin",
		Hostname:  "example.com",
		UserAgent: "bot/1.0",
		Action:    "block",
		RuleID:    "r1",
		RuleName:  "block-bot",
		Source:    "waf",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Hits:      3,
		WindowSec: 60,
	}
}

// TestNormalize_HappyPath verifies all fields are mapped correctly.
func TestNormalize_HappyPath(t *testing.T) {
	ev := baseEvent()
	out, err := cloudflareevent.Normalize(ev)
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if out.IP != "1.2.3.4" {
		t.Errorf("IP: want 1.2.3.4, got %q", out.IP)
	}
	if out.URI != "/admin" {
		t.Errorf("URI: want /admin, got %q", out.URI)
	}
	if out.Source != "waf" {
		t.Errorf("Source: want waf, got %q", out.Source)
	}
	if out.Hits != 3 {
		t.Errorf("Hits: want 3, got %d", out.Hits)
	}
	if out.WindowSec != 60 {
		t.Errorf("WindowSec: want 60, got %d", out.WindowSec)
	}
}

// TestNormalize_EmptyIP returns an error — IP is required.
func TestNormalize_EmptyIP(t *testing.T) {
	ev := baseEvent()
	ev.IP = ""
	_, err := cloudflareevent.Normalize(ev)
	if err == nil {
		t.Error("empty IP must return error")
	}
}

// TestNormalize_WhitespaceOnlyIP is treated as empty.
func TestNormalize_WhitespaceOnlyIP(t *testing.T) {
	ev := baseEvent()
	ev.IP = "   "
	_, err := cloudflareevent.Normalize(ev)
	if err == nil {
		t.Error("whitespace-only IP must return error")
	}
}

// TestNormalize_EmptyURI returns an error — URI is required.
func TestNormalize_EmptyURI(t *testing.T) {
	ev := baseEvent()
	ev.URI = ""
	_, err := cloudflareevent.Normalize(ev)
	if err == nil {
		t.Error("empty URI must return error")
	}
}

// TestNormalize_EmptySourceDefaultsToCloudflareWAF verifies that when Source is
// empty the normalize function substitutes "cloudflare_waf" (firstNonEmpty path).
func TestNormalize_EmptySourceDefaultsToCloudflareWAF(t *testing.T) {
	ev := baseEvent()
	ev.Source = ""
	out, err := cloudflareevent.Normalize(ev)
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if out.Source != "cloudflare_waf" {
		t.Errorf("empty source must default to 'cloudflare_waf', got %q", out.Source)
	}
}

// TestNormalize_WhitespaceSourceDefaultsToCloudflareWAF checks the trim path.
func TestNormalize_WhitespaceSourceDefaultsToCloudflareWAF(t *testing.T) {
	ev := baseEvent()
	ev.Source = "   "
	out, err := cloudflareevent.Normalize(ev)
	if err != nil {
		t.Fatalf("Normalize error: %v", err)
	}
	if out.Source != "cloudflare_waf" {
		t.Errorf("whitespace source must default to 'cloudflare_waf', got %q", out.Source)
	}
}

// TestNormalize_TimestampUTC verifies the timestamp is converted to UTC.
func TestNormalize_TimestampUTC(t *testing.T) {
	ev := baseEvent()
	loc, _ := time.LoadLocation("Europe/Paris")
	ev.Timestamp = time.Date(2026, 6, 1, 12, 0, 0, 0, loc)
	out, err := cloudflareevent.Normalize(ev)
	if err != nil {
		t.Fatal(err)
	}
	if out.Timestamp.Location() != time.UTC {
		t.Errorf("Timestamp must be UTC, got %v", out.Timestamp.Location())
	}
}

// TestNormalize_RayIDPassthrough verifies optional RayID is preserved.
func TestNormalize_RayIDPassthrough(t *testing.T) {
	ev := baseEvent()
	ev.RayID = "ray-abc123"
	out, err := cloudflareevent.Normalize(ev)
	if err != nil {
		t.Fatal(err)
	}
	if out.RayID != "ray-abc123" {
		t.Errorf("RayID not preserved: got %q", out.RayID)
	}
}

// TestNormalize_ZeroHits verifies that zero hits is valid (not filtered).
func TestNormalize_ZeroHits(t *testing.T) {
	ev := baseEvent()
	ev.Hits = 0
	_, err := cloudflareevent.Normalize(ev)
	if err != nil {
		t.Errorf("zero hits should be valid: %v", err)
	}
}
