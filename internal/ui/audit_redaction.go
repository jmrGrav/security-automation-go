package ui

import (
	"strings"

	shared "github.com/jm/security-automation-go/internal/security/redaction"
)

func isSensitiveAuditKey(key string) bool {
	k := strings.ToLower(strings.TrimSpace(key))
	switch {
	case strings.Contains(k, "secret"),
		strings.Contains(k, "token"),
		strings.Contains(k, "authorization"),
		strings.Contains(k, "auth_code"),
		strings.Contains(k, "code_verifier"),
		strings.Contains(k, "code_challenge"),
		strings.Contains(k, "client_secret"),
		strings.Contains(k, "api_key"),
		strings.Contains(k, "access_token"),
		strings.Contains(k, "refresh_token"),
		strings.Contains(k, "cookie"),
		strings.Contains(k, "session"),
		strings.Contains(k, "password"):
		return true
	default:
		return false
	}
}

func redactAuditValue(key string, value interface{}) interface{} {
	if isSensitiveAuditKey(key) {
		return "[REDACTED]"
	}

	switch v := value.(type) {
	case string:
		patterns := shared.DefaultPatterns()
		for _, re := range patterns {
			if re.MatchString(v) {
				return "[REDACTED]"
			}
		}
		return v
	case map[string]interface{}:
		redacted := make(map[string]interface{}, len(v))
		for k, nested := range v {
			redacted[k] = redactAuditValue(k, nested)
		}
		return redacted
	case []interface{}:
		redacted := make([]interface{}, len(v))
		for i, nested := range v {
			redacted[i] = redactAuditValue(key, nested)
		}
		return redacted
	default:
		return value
	}
}
