package fixtures

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSanitization(t *testing.T) {
	raw := RawFixture{
		FixtureID:  "fix-1",
		CapturedAt: time.Now(),
		Endpoint:   "/zones/1234567890abcdef1234567890abcdef/dns_records",
		Method:     "GET",
		ResponseHeaders: map[string]string{
			"X-Auth-Email": "admin@example.com",
		},
		ResponseBody: []byte(`{"result": [{"id": "abcdef1234567890abcdef1234567890", "email": "user@example.com"}]}`),
	}

	sanitized := Sanitize(raw, "v1")

	if strings.Contains(string(sanitized.ResponseBody), "user@example.com") {
		t.Error("body still contains sensitive email")
	}
	if strings.Contains(string(sanitized.ResponseBody), "abcdef1234567890abcdef1234567890") {
		t.Error("body still contains sensitive ID")
	}
	if sanitized.ResponseHeaders["X-Auth-Email"] != "[REDACTED_HEADER]" {
		t.Error("header not redacted correctly")
	}

	if !IsIrreversible(sanitized) {
		t.Error("sanitized fixture failed irreversibility check")
	}
}

func TestDeterministicReplay(t *testing.T) {
	f1 := SanitizedFixture{SourceFixtureID: "f1", ResponseStatus: 200, ResponseBody: []byte("one")}
	f1.IntegrityHash = IntegrityHashSanitized(f1)
	f2 := SanitizedFixture{SourceFixtureID: "f2", ResponseStatus: 200, ResponseBody: []byte("two")}
	f2.IntegrityHash = IntegrityHashSanitized(f2)

	meta := ReplayMetadata{
		Ordering: []string{"f1", "f2", "f1"},
	}

	engine := NewReplayEngine([]SanitizedFixture{f1, f2}, meta)
	ctx := context.Background()

	res1, _ := engine.Next(ctx)
	if res1.Response.SourceFixtureID != "f1" {
		t.Errorf("expected f1, got %s", res1.Response.SourceFixtureID)
	}

	res2, _ := engine.Next(ctx)
	if res2.Response.SourceFixtureID != "f2" {
		t.Errorf("expected f2, got %s", res2.Response.SourceFixtureID)
	}

	res3, _ := engine.Next(ctx)
	if res3.Response.SourceFixtureID != "f1" {
		t.Errorf("expected f1 (second time), got %s", res3.Response.SourceFixtureID)
	}

	_, err := engine.Next(ctx)
	if err == nil || err.Error() != "EOF" {
		t.Error("expected EOF")
	}
}

func TestFailureInjection(t *testing.T) {
	f1 := SanitizedFixture{SourceFixtureID: "f1", ResponseStatus: 200}
	f1.IntegrityHash = IntegrityHashSanitized(f1)

	meta := ReplayMetadata{
		Ordering: []string{"f1"},
		FailureInjections: []FailureTrigger{
			{FixtureID: "f1", Type: FailRateLimit, Chance: 1.0},
		},
	}

	engine := NewReplayEngine([]SanitizedFixture{f1}, meta)
	res, err := engine.Next(context.Background())

	if err != nil {
		t.Fatalf("Next should not return error, ReplayResult.Error should: %v", err)
	}
	if res.Error != ErrInjectedRateLimit {
		t.Errorf("expected injected rate limit error, got %v", res.Error)
	}
}

func TestIntegrityValidation(t *testing.T) {
	f1 := SanitizedFixture{SourceFixtureID: "f1", ResponseStatus: 200, IntegrityHash: "wrong"}

	err := ValidateIntegrity(f1)
	if err == nil || !strings.Contains(err.Error(), "integrity check failed") {
		t.Error("expected integrity failure")
	}
}
