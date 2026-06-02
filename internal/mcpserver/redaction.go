package mcpserver

import (
	"encoding/json"

	shared "github.com/jm/security-automation-go/internal/security/redaction"
)

// RedactJSON redacts sensitive values from a JSON string or byte slice.
func RedactJSON(input []byte) []byte {
	var data interface{}
	if err := json.Unmarshal(input, &data); err != nil {
		return input
	}
	redacted := redactRecursive(data)
	out, err := json.Marshal(redacted)
	if err != nil {
		return input
	}
	return out
}

func redactRecursive(data interface{}) interface{} {
	switch v := data.(type) {
	case string:
		patterns := shared.DefaultPatterns()
		for _, re := range patterns {
			if re.MatchString(v) {
				return "[redacted]"
			}
		}
		return v
	case map[string]interface{}:
		for k, val := range v {
			if isSensitiveKey(k) {
				v[k] = "[redacted]"
			} else {
				v[k] = redactRecursive(val)
			}
		}
		return v
	case []interface{}:
		for i, val := range v {
			v[i] = redactRecursive(val)
		}
		return v
	default:
		return data
	}
}

func isSensitiveKey(key string) bool {
	// Re-use logic or patterns from internal/security/redaction
	return shared.KeyValueRe.MatchString(key + "=fake")
}
