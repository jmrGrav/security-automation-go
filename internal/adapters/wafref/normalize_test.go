package wafref

import (
	"testing"
	"time"
)

func TestNormalizeRequiresIP(t *testing.T) {
	_, err := Normalize(RawEvent{Ref: "ABC123", Timestamp: time.Now()})
	if err == nil {
		t.Fatal("expected error for missing ip")
	}
}

func TestNormalizeRequiresRef(t *testing.T) {
	_, err := Normalize(RawEvent{IP: "8.8.8.8", Timestamp: time.Now()})
	if err == nil {
		t.Fatal("expected error for missing ref")
	}
}

func TestNormalizeCarriesRefThrough(t *testing.T) {
	ts := time.Now().UTC()
	event, err := Normalize(RawEvent{
		Ref:       "1A2B3C-DEF012",
		Timestamp: ts,
		IP:        "8.8.8.8",
		Host:      "arleo.eu",
		Method:    "GET",
		URI:       "/?q=<script>alert(1)</script>",
		Reason:    "appsec",
	})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if event.Ref != "1A2B3C-DEF012" {
		t.Fatalf("expected ref to carry through, got %q", event.Ref)
	}
	if event.IP != "8.8.8.8" || event.Hostname != "arleo.eu" || event.HTTPMethod != "GET" {
		t.Fatalf("unexpected event: %+v", event)
	}
	if event.URI != "/?q=<script>alert(1)</script>" {
		t.Fatalf("unexpected uri: %q", event.URI)
	}
	if event.RuleName != "appsec" {
		t.Fatalf("expected rule name to default to reason, got %q", event.RuleName)
	}
	if event.Action != "block" {
		t.Fatalf("expected action=block, got %q", event.Action)
	}
}

func TestNormalizeDefaultsMissingURIAndReason(t *testing.T) {
	event, err := Normalize(RawEvent{Ref: "REF1", IP: "1.2.3.4", Timestamp: time.Now()})
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if event.URI != "unknown" {
		t.Fatalf("expected default uri, got %q", event.URI)
	}
	if event.RuleName != "waf_block" {
		t.Fatalf("expected default rule name, got %q", event.RuleName)
	}
}
