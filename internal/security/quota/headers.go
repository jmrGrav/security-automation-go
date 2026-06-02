package quota

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ParseCloudflareHeaders extracts normalized quota observations from Cloudflare responses.
func ParseCloudflareHeaders(h http.Header) Observation {
	now := time.Now().UTC()
	obs := Observation{
		Provider:    "cloudflare",
		Plan:        "cloudflare quota headers",
		QuotaSource: "headers",
		ObservedAt:  now,
	}

	if h == nil {
		return ClassifyObservation(obs)
	}

	if raw := strings.TrimSpace(h.Get("Ratelimit-Policy")); raw != "" {
		obs.Notes = append(obs.Notes, "Ratelimit-Policy="+raw)
		applyCloudflareStructuredFields(&obs, raw, now)
	}
	if raw := strings.TrimSpace(h.Get("Ratelimit")); raw != "" {
		applyCloudflareStructuredFields(&obs, raw, now)
	}
	if retry := parseRetryAfterHeader(h.Get("Retry-After")); retry != nil {
		obs.ResetKnown = true
		obs.ResetAt = now.Add(*retry)
		obs.Notes = append(obs.Notes, "Retry-After="+retry.String())
	}

	if obs.LimitKnown && obs.RemainingKnown {
		obs.Used = clampNonNegative(obs.Limit - obs.Remaining)
		obs.UsedKnown = true
	}

	return ClassifyObservation(obs)
}

// ParseAbuseIPDBHeaders extracts normalized quota observations from AbuseIPDB responses.
func ParseAbuseIPDBHeaders(h http.Header) Observation {
	now := time.Now().UTC()
	obs := Observation{
		Provider:    "abuseipdb",
		Plan:        "abuseipdb api quota",
		QuotaSource: "headers",
		ObservedAt:  now,
	}

	if h == nil {
		return ClassifyObservation(obs)
	}

	if raw := strings.TrimSpace(h.Get("X-RateLimit-Policy")); raw != "" {
		obs.Notes = append(obs.Notes, "X-RateLimit-Policy="+raw)
		applyAbuseIPDBStructuredFields(&obs, raw, now)
	}
	if raw := strings.TrimSpace(h.Get("X-RateLimit-Limit")); raw != "" {
		if limit, ok := parseFloat64(raw); ok {
			obs.Limit = limit
			obs.LimitKnown = true
		}
	}
	if raw := strings.TrimSpace(h.Get("X-RateLimit-Remaining")); raw != "" {
		if remaining, ok := parseFloat64(raw); ok {
			obs.Remaining = remaining
			obs.RemainingKnown = true
		}
	}
	if raw := strings.TrimSpace(h.Get("X-RateLimit-Reset")); raw != "" {
		if reset, ok := parseRateLimitReset(raw, now); ok {
			obs.ResetAt = reset
			obs.ResetKnown = true
		}
	}
	if raw := strings.TrimSpace(h.Get("X-RateLimit-Reset-After")); raw != "" {
		if resetAfter, ok := parseDurationSeconds(raw); ok {
			obs.ResetAt = now.Add(resetAfter)
			obs.ResetKnown = true
		}
	}
	if retry := parseRetryAfterHeader(h.Get("Retry-After")); retry != nil {
		obs.ResetAt = now.Add(*retry)
		obs.ResetKnown = true
		obs.Notes = append(obs.Notes, "Retry-After="+retry.String())
	}

	if obs.LimitKnown && obs.RemainingKnown {
		obs.Used = clampNonNegative(obs.Limit - obs.Remaining)
		obs.UsedKnown = true
	}

	return ClassifyObservation(obs)
}

// CloudflareRetryAfter extracts Retry-After as a duration and stays neutral when absent.
func CloudflareRetryAfter(resp *http.Response) time.Duration {
	if resp == nil {
		return 0
	}
	if retry := parseRetryAfterHeader(resp.Header.Get("Retry-After")); retry != nil {
		return *retry
	}
	return 0
}

func applyCloudflareStructuredFields(obs *Observation, raw string, now time.Time) {
	fields := parseStructuredFields(raw)

	if limit, ok := fields["q"]; ok {
		if parsed, ok := parseFloat64(limit); ok {
			obs.Limit = parsed
			obs.LimitKnown = true
		}
	}
	if limit, ok := fields["limit"]; ok && !obs.LimitKnown {
		if parsed, ok := parseFloat64(limit); ok {
			obs.Limit = parsed
			obs.LimitKnown = true
		}
	}
	if remaining, ok := fields["r"]; ok {
		if parsed, ok := parseFloat64(remaining); ok {
			obs.Remaining = parsed
			obs.RemainingKnown = true
		}
	}
	if remaining, ok := fields["remaining"]; ok && !obs.RemainingKnown {
		if parsed, ok := parseFloat64(remaining); ok {
			obs.Remaining = parsed
			obs.RemainingKnown = true
		}
	}
	if reset, ok := fields["t"]; ok {
		if parsed, ok := parseDurationSeconds(reset); ok {
			obs.ResetAt = now.Add(parsed)
			obs.ResetKnown = true
		}
	}
	if reset, ok := fields["reset"]; ok && !obs.ResetKnown {
		if parsed, ok := parseDurationSeconds(reset); ok {
			obs.ResetAt = now.Add(parsed)
			obs.ResetKnown = true
		}
	}
	if reset, ok := fields["reset"]; ok && !obs.ResetKnown {
		if parsed, ok := parseDurationSeconds(reset); ok {
			obs.ResetAt = now.Add(parsed)
			obs.ResetKnown = true
		}
	}
	if reset, ok := fields["reset-after"]; ok && !obs.ResetKnown {
		if parsed, ok := parseDurationSeconds(reset); ok {
			obs.ResetAt = now.Add(parsed)
			obs.ResetKnown = true
		}
	}
	if window, ok := fields["window"]; ok && !obs.ResetKnown {
		if parsed, ok := parseDurationSeconds(window); ok {
			obs.ResetAt = now.Add(parsed)
			obs.ResetKnown = true
		}
	}
	if window, ok := fields["w"]; ok && !obs.ResetKnown {
		if parsed, ok := parseDurationSeconds(window); ok {
			obs.ResetAt = now.Add(parsed)
			obs.ResetKnown = true
		}
	}
	if window, ok := fields["w"]; ok && !obs.ResetKnown {
		if parsed, ok := parseDurationSeconds(window); ok {
			obs.ResetAt = now.Add(parsed)
			obs.ResetKnown = true
		}
	}
	if policy, ok := fields["policy"]; ok {
		obs.Notes = append(obs.Notes, "policy="+policy)
	}
}

func applyAbuseIPDBStructuredFields(obs *Observation, raw string, now time.Time) {
	fields := parseStructuredFields(raw)
	if limit, ok := fields["limit"]; ok {
		if parsed, ok := parseFloat64(limit); ok {
			obs.Limit = parsed
			obs.LimitKnown = true
		}
	}
	if remaining, ok := fields["remaining"]; ok {
		if parsed, ok := parseFloat64(remaining); ok {
			obs.Remaining = parsed
			obs.RemainingKnown = true
		}
	}
	if reset, ok := fields["reset"]; ok && !obs.ResetKnown {
		if parsed, ok := parseRateLimitReset(reset, now); ok {
			obs.ResetAt = parsed
			obs.ResetKnown = true
		}
	}
	if window, ok := fields["window"]; ok && !obs.ResetKnown {
		if parsed, ok := parseDurationSeconds(window); ok {
			obs.ResetAt = now.Add(parsed)
			obs.ResetKnown = true
		}
	}
	if policy, ok := fields["policy"]; ok {
		obs.Notes = append(obs.Notes, "policy="+policy)
	}
}

func parseStructuredFields(raw string) map[string]string {
	fields := make(map[string]string)
	for _, part := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ';'
	}) {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		key, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.Trim(strings.TrimSpace(value), `"`)
		if key != "" && value != "" {
			fields[key] = value
		}
	}
	return fields
}

func parseFloat64(raw string) (float64, bool) {
	value, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return 0, false
	}
	return value, true
}

func parseDurationSeconds(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, false
	}
	secs, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}

func parseRetryAfterHeader(raw string) *time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if d, ok := parseDurationSeconds(raw); ok {
		return &d
	}
	if when, err := http.ParseTime(raw); err == nil {
		d := time.Until(when)
		if d < 0 {
			d = 0
		}
		return &d
	}
	return nil
}

func parseRateLimitReset(raw string, now time.Time) (time.Time, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Time{}, false
	}
	if unix, err := strconv.ParseInt(raw, 10, 64); err == nil {
		if unix >= 1_000_000_000 {
			return time.Unix(unix, 0).UTC(), true
		}
		if unix >= 0 {
			return now.Add(time.Duration(unix) * time.Second), true
		}
	}
	return time.Time{}, false
}
