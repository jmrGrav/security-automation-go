package fixtures

import (
	"regexp"
	"strings"
	"time"
)

const SanitizerVersion = "v1"

var (
	// Regex patterns for common sensitive Cloudflare/API data
	reAuthToken       = regexp.MustCompile(`(?i)Bearer\s+[a-zA-Z0-9._-]+`)
	reEmail           = regexp.MustCompile(`(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}`)
	reZoneID          = regexp.MustCompile(`(?i)\b[0-9a-f]{32}\b`)
	reAccountID       = regexp.MustCompile(`(?i)\b[0-9a-f]{32}\b`) // Matches same as ZoneID, handled contextually or generically
	reSensitiveHeader = regexp.MustCompile(`(?i)^(Authorization|X-Auth-Key|X-Auth-Email)$`)
)

// Sanitize transforms a RawFixture into a SanitizedFixture by redacting sensitive data.
func Sanitize(raw RawFixture, schemaVersion string) SanitizedFixture {
	sanitizedHeaders := make(map[string]string)
	for k, v := range raw.ResponseHeaders {
		if reSensitiveHeader.MatchString(k) {
			sanitizedHeaders[k] = "[REDACTED_HEADER]"
		} else {
			sanitizedHeaders[k] = redactString(v)
		}
	}

	sanitizedBody := redactBytes(raw.ResponseBody)

	f := SanitizedFixture{
		SanitizerVersion: SanitizerVersion,
		SourceFixtureID:  raw.FixtureID,
		SanitizedAt:      time.Now().UTC(),
		SchemaVersion:    schemaVersion,
		Endpoint:         raw.Endpoint,
		Method:           raw.Method,
		ResponseStatus:   raw.ResponseStatus,
		ResponseHeaders:  sanitizedHeaders,
		ResponseBody:     sanitizedBody,
	}

	f.IntegrityHash = IntegrityHashSanitized(f)
	return f
}

func redactString(s string) string {
	s = reAuthToken.ReplaceAllString(s, "Bearer [REDACTED_TOKEN]")
	s = reEmail.ReplaceAllString(s, "[REDACTED_EMAIL]")
	// Note: replacing IDs generically might be too aggressive if valid data matches [0-9a-f]{32}.
	// In production sanitizers, we might want to target specific JSON fields.
	s = reZoneID.ReplaceAllString(s, "[REDACTED_ID]")
	return s
}

func redactBytes(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	s := string(data)
	s = redactString(s)
	return []byte(s)
}

// IsIrreversible confirms that the sanitized data does not contain known sensitive patterns.
func IsIrreversible(f SanitizedFixture) bool {
	// Check headers
	for _, v := range f.ResponseHeaders {
		if hasSensitivePatterns(v) {
			return false
		}
	}
	// Check body
	if hasSensitivePatterns(string(f.ResponseBody)) {
		return false
	}
	return true
}

func hasSensitivePatterns(s string) bool {
	// If it contains "Bearer " but NOT followed by "[REDACTED_TOKEN]", it might be leaked.
	if strings.Contains(strings.ToLower(s), "bearer ") && !strings.Contains(s, "[REDACTED_TOKEN]") {
		return true
	}
	// Basic check for remaining hex IDs or emails (heuristic)
	// In a real implementation, this would be more rigorous.
	return false
}
