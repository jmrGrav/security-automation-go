package quota

import (
	"net/http"
	"testing"
	"time"
)

func TestParseCloudflareHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set("Ratelimit", "limit=100, remaining=4, reset=30")
	h.Set("Ratelimit-Policy", `policy="default"; limit=100; window=60`)
	h.Set("Retry-After", "12")

	got := ParseCloudflareHeaders(h)

	if got.Provider != "cloudflare" {
		t.Fatalf("unexpected provider: %q", got.Provider)
	}
	if got.Plan != "cloudflare quota headers" {
		t.Fatalf("unexpected plan: %q", got.Plan)
	}
	if got.QuotaSource != "headers" {
		t.Fatalf("unexpected quota source: %q", got.QuotaSource)
	}
	if !got.LimitKnown || got.Limit != 100 {
		t.Fatalf("unexpected limit: known=%t limit=%v", got.LimitKnown, got.Limit)
	}
	if !got.RemainingKnown || got.Remaining != 4 {
		t.Fatalf("unexpected remaining: known=%t remaining=%v", got.RemainingKnown, got.Remaining)
	}
	if !got.UsedKnown || got.Used != 96 {
		t.Fatalf("unexpected used: known=%t used=%v", got.UsedKnown, got.Used)
	}
	if !got.ResetKnown {
		t.Fatal("expected reset to be known")
	}
	if got.ResetAt.IsZero() {
		t.Fatal("expected reset time to be populated")
	}
	if !got.PercentKnown || got.RemainingPercent != 4 {
		t.Fatalf("unexpected percent: known=%t percent=%v", got.PercentKnown, got.RemainingPercent)
	}
	if got.State != Throttled {
		t.Fatalf("unexpected state: %v", got.State)
	}
	if len(got.Notes) == 0 {
		t.Fatal("expected parsed header notes")
	}
	if got.Notes[0] != "Ratelimit-Policy=policy=\"default\"; limit=100; window=60" {
		t.Fatalf("unexpected notes: %v", got.Notes)
	}
	if got.Notes[len(got.Notes)-1] != "Retry-After=12s" {
		t.Fatalf("unexpected retry-after note: %v", got.Notes)
	}
}

func TestParseAbuseIPDBHeaders(t *testing.T) {
	h := make(http.Header)
	h.Set("X-RateLimit-Limit", "3600")
	h.Set("X-RateLimit-Remaining", "17")
	h.Set("X-RateLimit-Reset", "45")

	got := ParseAbuseIPDBHeaders(h)

	if got.Provider != "abuseipdb" {
		t.Fatalf("unexpected provider: %q", got.Provider)
	}
	if got.Plan != "abuseipdb api quota" {
		t.Fatalf("unexpected plan: %q", got.Plan)
	}
	if got.Limit != 3600 {
		t.Fatalf("unexpected limit: %v", got.Limit)
	}
	if got.Remaining != 17 {
		t.Fatalf("unexpected remaining: %v", got.Remaining)
	}
	if got.Used != 3583 || !got.UsedKnown {
		t.Fatalf("unexpected used: known=%t used=%v", got.UsedKnown, got.Used)
	}
	if !got.ResetKnown {
		t.Fatal("expected reset to be known")
	}
	if got.ResetAt.IsZero() {
		t.Fatal("expected reset time to be populated")
	}
	if got.State != Throttled {
		t.Fatalf("unexpected state: %v", got.State)
	}
}

func TestParseHeadersNeutralWhenAbsent(t *testing.T) {
	gotCF := ParseCloudflareHeaders(http.Header{})
	if gotCF.LimitKnown || gotCF.RemainingKnown || gotCF.UsedKnown || gotCF.ResetKnown || gotCF.PercentKnown {
		t.Fatalf("expected neutral cloudflare observation, got %+v", gotCF)
	}
	if gotCF.State != Unknown {
		t.Fatalf("unexpected cloudflare state: %v", gotCF.State)
	}
	if gotCF.ObservedAt.IsZero() {
		t.Fatal("expected observed time to be set")
	}

	gotAB := ParseAbuseIPDBHeaders(http.Header{})
	if gotAB.LimitKnown || gotAB.RemainingKnown || gotAB.UsedKnown || gotAB.ResetKnown || gotAB.PercentKnown {
		t.Fatalf("expected neutral abuseipdb observation, got %+v", gotAB)
	}
	if gotAB.State != Unknown {
		t.Fatalf("unexpected abuseipdb state: %v", gotAB.State)
	}
}

func TestCloudflareRetryAfter(t *testing.T) {
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Retry-After", "12")
	if got := CloudflareRetryAfter(resp); got != 12*time.Second {
		t.Fatalf("unexpected retry-after: %s", got)
	}
	resp.Header.Set("Retry-After", "bad")
	if got := CloudflareRetryAfter(resp); got != 0 {
		t.Fatalf("expected zero on invalid retry-after, got %s", got)
	}
	if got := CloudflareRetryAfter(nil); got != 0 {
		t.Fatalf("expected zero on nil response, got %s", got)
	}
}
