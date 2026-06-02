package quota

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ParseOpenAIHeaders builds a quota observation from OpenAI rate-limit headers.
func ParseOpenAIHeaders(h http.Header) ProviderQuota {
	now := time.Now().UTC()
	q := ProviderQuota{
		Provider:       "openai",
		State:          Unknown,
		Source:         "headers",
		LastObservedAt: now,
	}
	if h == nil {
		return q
	}
	reqLimit, reqLimitOK := parseHeaderInt(h.Get("x-ratelimit-limit-requests"))
	reqRemain, reqRemainOK := parseHeaderInt(h.Get("x-ratelimit-remaining-requests"))
	tokLimit, tokLimitOK := parseHeaderInt(h.Get("x-ratelimit-limit-tokens"))
	tokRemain, tokRemainOK := parseHeaderInt(h.Get("x-ratelimit-remaining-tokens"))
	if reqLimitOK {
		q.RequestsLimit = reqLimit
	}
	if reqLimitOK && reqRemainOK {
		q.RequestsUsed, q.RequestsRemain = deriveUsage(reqLimit, reqRemain)
	}
	if tokLimitOK {
		q.TokensLimit = tokLimit
	}
	if tokLimitOK && tokRemainOK {
		q.TokensUsed, q.TokensRemain = deriveUsage(tokLimit, tokRemain)
	}
	if reset := parseDurationHeader(h.Get("x-ratelimit-reset-requests")); reset != nil {
		resetAt := now.Add(*reset)
		q.ResetAt = &resetAt
		q.ResetKnown = true
	}
	if reset := parseDurationHeader(h.Get("x-ratelimit-reset-tokens")); reset != nil {
		resetAt := now.Add(*reset)
		q.ResetAt = &resetAt
		q.ResetKnown = true
	}
	if retry := parseRetryAfterHeader(h.Get("retry-after")); retry != nil {
		q.RetryAfter = retry
		resetAt := now.Add(*retry)
		q.ResetAt = &resetAt
		q.ResetKnown = true
	}
	return classifyObservedQuota(q, reqLimitOK && reqRemainOK, tokLimitOK && tokRemainOK)
}

// ParseAnthropicHeaders builds a quota observation from Anthropic rate-limit headers.
func ParseAnthropicHeaders(h http.Header) ProviderQuota {
	now := time.Now().UTC()
	q := ProviderQuota{
		Provider:       "anthropic",
		State:          Unknown,
		Source:         "headers",
		LastObservedAt: now,
	}
	if h == nil {
		return q
	}
	reqLimit, reqLimitOK := parseHeaderInt(h.Get("anthropic-ratelimit-requests-limit"))
	reqRemain, reqRemainOK := parseHeaderInt(h.Get("anthropic-ratelimit-requests-remaining"))
	tokLimit, tokLimitOK := parseHeaderInt(h.Get("anthropic-ratelimit-tokens-limit"))
	tokRemain, tokRemainOK := parseHeaderInt(h.Get("anthropic-ratelimit-tokens-remaining"))
	if reqLimitOK {
		q.RequestsLimit = reqLimit
	}
	if reqLimitOK && reqRemainOK {
		q.RequestsUsed, q.RequestsRemain = deriveUsage(reqLimit, reqRemain)
	}
	if tokLimitOK {
		q.TokensLimit = tokLimit
	}
	if tokLimitOK && tokRemainOK {
		q.TokensUsed, q.TokensRemain = deriveUsage(tokLimit, tokRemain)
	}
	if reset := parseTimeHeader(h.Get("anthropic-ratelimit-requests-reset")); reset != nil {
		q.ResetAt = reset
		q.ResetKnown = true
	}
	if reset := parseTimeHeader(h.Get("anthropic-ratelimit-tokens-reset")); reset != nil {
		q.ResetAt = reset
		q.ResetKnown = true
	}
	if retry := parseRetryAfterHeader(h.Get("retry-after")); retry != nil {
		q.RetryAfter = retry
		resetAt := now.Add(*retry)
		q.ResetAt = &resetAt
		q.ResetKnown = true
	}
	return classifyObservedQuota(q, reqLimitOK && reqRemainOK, tokLimitOK && tokRemainOK)
}

// ParseFailureObservation classifies a failed request into a retryable quota posture.
func ParseFailureObservation(provider string, status int, h http.Header, body []byte) ProviderQuota {
	base := ProviderQuota{
		Provider:       normalizeProvider(provider),
		State:          Unknown,
		Source:         "status",
		LastObservedAt: time.Now().UTC(),
	}
	return ObserveFailure(base, status, h, body)
}

// ObserveFailure merges a known quota observation with a failed request.
func ObserveFailure(base ProviderQuota, status int, h http.Header, body []byte) ProviderQuota {
	now := time.Now().UTC()
	q := base.clone()
	q.LastObservedAt = now
	q.Source = "status"
	if q.State == Disabled {
		return q
	}
	if q.Provider == "" {
		q.Provider = "unknown"
	}

	retry := parseRetryAfterHeader(headerValue(h, "retry-after"))
	if retry != nil {
		q.RetryAfter = retry
		resetAt := now.Add(*retry)
		q.ResetAt = &resetAt
		q.ResetKnown = true
	}

	switch {
	case status == http.StatusTooManyRequests:
		if bodyLooksLikeExhaustion(body) || retry == nil {
			q.State = Exhausted
		} else {
			q.State = Throttled
		}
	case status == http.StatusServiceUnavailable || status == http.StatusGatewayTimeout || status == http.StatusRequestTimeout:
		q.State = Cooldown
	default:
		if retry != nil && q.State == Unknown {
			q.State = Throttled
		}
	}

	if q.State == Unknown {
		q.State = classifyFromHeaders(q)
	}
	return q
}

func classifyObservedQuota(q ProviderQuota, requestsKnown, tokensKnown bool) ProviderQuota {
	if q.State == Disabled {
		return q
	}
	if requestsKnown && q.RequestsLimit > 0 && q.RequestsRemain <= 0 {
		q.State = Exhausted
		return q
	}
	if tokensKnown && q.TokensLimit > 0 && q.TokensRemain <= 0 {
		q.State = Exhausted
		return q
	}

	percent := observedRemainingPercent(q, requestsKnown, tokensKnown)
	switch {
	case percent <= 0:
		q.State = Exhausted
	case percent <= 5:
		q.State = Throttled
	case percent <= 20:
		q.State = Warning
	case (requestsKnown && q.RequestsLimit > 0) || (tokensKnown && q.TokensLimit > 0):
		q.State = Normal
	}

	if q.State == Unknown && q.RetryAfter != nil {
		q.State = Throttled
	}
	return q
}

func classifyFromHeaders(q ProviderQuota) State {
	requestsKnown := q.RequestsLimit > 0 && (q.RequestsUsed > 0 || q.RequestsRemain > 0)
	tokensKnown := q.TokensLimit > 0 && (q.TokensUsed > 0 || q.TokensRemain > 0)
	percent := observedRemainingPercent(q, requestsKnown, tokensKnown)
	switch {
	case percent <= 0:
		return Exhausted
	case percent <= 5:
		return Throttled
	case percent <= 20:
		return Warning
	case requestsKnown || tokensKnown:
		return Normal
	default:
		return Unknown
	}
}

func observedRemainingPercent(q ProviderQuota, requestsKnown, tokensKnown bool) float64 {
	best := -1.0
	if requestsKnown && q.RequestsLimit > 0 {
		remaining := float64(q.RequestsRemain)
		percent := (remaining / float64(q.RequestsLimit)) * 100
		best = percent
	}
	if tokensKnown && q.TokensLimit > 0 {
		remaining := float64(q.TokensRemain)
		percent := (remaining / float64(q.TokensLimit)) * 100
		if best < 0 || percent < best {
			best = percent
		}
	}
	if best < 0 {
		return 100
	}
	return best
}

func parseHeaderInt(raw string) (int, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	if parsed, err := strconv.Atoi(raw); err == nil {
		return parsed, true
	}
	if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
		return int(parsed), true
	}
	return 0, false
}

func deriveUsage(limit, remaining int) (used, remain int) {
	if limit <= 0 {
		return 0, remaining
	}
	if remaining < 0 {
		remaining = 0
	}
	if remaining > limit {
		remaining = limit
	}
	return limit - remaining, remaining
}

func parseDurationHeader(raw string) *time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if parsed, err := time.ParseDuration(raw); err == nil {
		return &parsed
	}
	if secs, err := strconv.ParseFloat(raw, 64); err == nil {
		d := time.Duration(secs * float64(time.Second))
		return &d
	}
	return nil
}

func parseTimeHeader(raw string) *time.Time {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		parsed = parsed.UTC()
		return &parsed
	}
	if parsed, err := http.ParseTime(raw); err == nil {
		parsed = parsed.UTC()
		return &parsed
	}
	return nil
}

func parseRetryAfterHeader(raw string) *time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if parsed, err := strconv.Atoi(raw); err == nil {
		d := time.Duration(parsed) * time.Second
		return &d
	}
	if parsed, err := http.ParseTime(raw); err == nil {
		d := time.Until(parsed.UTC())
		if d < 0 {
			zero := time.Duration(0)
			return &zero
		}
		return &d
	}
	return nil
}

func bodyLooksLikeExhaustion(body []byte) bool {
	trimmed := strings.ToLower(strings.TrimSpace(string(body)))
	if trimmed == "" {
		return false
	}
	for _, needle := range []string{"quota", "exhaust", "rate limit", "resource_exhausted"} {
		if strings.Contains(trimmed, needle) {
			return true
		}
	}
	return false
}

func headerValue(h http.Header, name string) string {
	if h == nil {
		return ""
	}
	return h.Get(name)
}
