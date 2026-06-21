package nginxerrors

import (
	"net/netip"
	"testing"
	"time"
)

func TestNormalizeRequiresIP(t *testing.T) {
	_, err := Normalize(RawEvent{Status: 404, Timestamp: time.Now()})
	if err == nil {
		t.Fatal("expected error for missing ip")
	}
}

func TestNormalizeRequiresErrorStatus(t *testing.T) {
	ip := netip.MustParseAddr("8.8.8.8")
	for _, status := range []int{0, 200, 301, 399, 600} {
		if _, err := Normalize(RawEvent{IP: ip, Status: status, Timestamp: time.Now()}); err == nil {
			t.Fatalf("expected error for non-error status %d", status)
		}
	}
}

func TestNormalizeCarriesFieldsThrough(t *testing.T) {
	ts := time.Now().UTC()
	ip := netip.MustParseAddr("9.9.9.9")
	event, err := Normalize(RawEvent{
		IP:        ip,
		Timestamp: ts,
		Method:    "GET",
		URI:       "/.env",
		Status:    404,
		UserAgent: "curl/8.0",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if event.IP != "9.9.9.9" || event.HTTPMethod != "GET" || event.UserAgent != "curl/8.0" {
		t.Fatalf("unexpected event: %+v", event)
	}
	if event.URI != "/.env" {
		t.Fatalf("unexpected uri: %q", event.URI)
	}
	if event.EdgeResponseStatus != 404 {
		t.Fatalf("expected status to carry through, got %d", event.EdgeResponseStatus)
	}
	if event.RuleName != "http_404" {
		t.Fatalf("unexpected rule name: %q", event.RuleName)
	}
	if event.Action != "http_error" {
		t.Fatalf("expected action=http_error, got %q", event.Action)
	}
}

func TestNormalizeDefaultsMissingURI(t *testing.T) {
	ip := netip.MustParseAddr("1.2.3.4")
	event, err := Normalize(RawEvent{IP: ip, Status: 500, Timestamp: time.Now()})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if event.URI != "unknown" {
		t.Fatalf("expected default uri, got %q", event.URI)
	}
}
