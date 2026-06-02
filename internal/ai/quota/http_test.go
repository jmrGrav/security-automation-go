package quota

import (
	"net/http"
	"testing"
	"time"
)

func TestParseOpenAIHeaders(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set("x-ratelimit-limit-requests", "10")
	h.Set("x-ratelimit-remaining-requests", "2")
	h.Set("x-ratelimit-limit-tokens", "100")
	h.Set("x-ratelimit-remaining-tokens", "80")
	q := ParseOpenAIHeaders(h)
	if q.State != Warning {
		t.Fatalf("unexpected state: %+v", q)
	}
	if q.RequestsRemain != 2 || q.TokensRemain != 80 {
		t.Fatalf("unexpected quota values: %+v", q)
	}
}

func TestParseAnthropicHeadersAndObserveFailure(t *testing.T) {
	t.Parallel()

	h := http.Header{}
	h.Set("anthropic-ratelimit-requests-limit", "20")
	h.Set("anthropic-ratelimit-requests-remaining", "0")
	h.Set("retry-after", "3")
	q := ParseAnthropicHeaders(h)
	if q.State != Exhausted {
		t.Fatalf("unexpected state: %+v", q)
	}

	failure := ObserveFailure(q, http.StatusTooManyRequests, h, []byte(`{"error":{"message":"quota exceeded"}}`))
	if failure.State != Exhausted {
		t.Fatalf("unexpected failure state: %+v", failure)
	}
	if failure.RetryAfter == nil || *failure.RetryAfter != 3*time.Second {
		t.Fatalf("unexpected retry-after: %+v", failure)
	}
}

func TestCanUseAndBetter(t *testing.T) {
	t.Parallel()

	exhausted := ProviderQuota{Provider: "openai", State: Exhausted}
	normal := ProviderQuota{Provider: "anthropic", State: Normal, TokensRemain: 80, RequestsRemain: 19}
	if CanUse(exhausted) {
		t.Fatalf("expected exhausted quota to be skipped")
	}
	if !CanUse(normal) {
		t.Fatalf("expected normal quota to be usable")
	}
	if !Better(normal, exhausted) {
		t.Fatalf("expected normal quota to win fallback ordering")
	}
}

func TestCanUseAtReactivatesExpiredQuota(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, time.June, 1, 12, 0, 0, 0, time.UTC)
	past := now.Add(-3 * time.Minute)
	future := now.Add(time.Minute)
	retry := 2 * time.Minute

	expiredReset := ProviderQuota{Provider: "openai", State: Exhausted, ResetAt: &past}
	if !CanUseAt(expiredReset, now) {
		t.Fatalf("expected exhausted quota with past reset to be reusable: %+v", expiredReset)
	}

	expiredRetry := ProviderQuota{Provider: "anthropic", State: Cooldown, LastObservedAt: past, RetryAfter: &retry}
	if !CanUseAt(expiredRetry, now) {
		t.Fatalf("expected cooldown quota with elapsed retry-after to be reusable: %+v", expiredRetry)
	}

	inFlightReset := ProviderQuota{Provider: "gemini", State: Exhausted, ResetAt: &future}
	if CanUseAt(inFlightReset, now) {
		t.Fatalf("expected future reset to remain blocked: %+v", inFlightReset)
	}
}
