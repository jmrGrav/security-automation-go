package ui

import (
	"testing"
)

func TestAuditRedactionMasksSensitiveKeysAndValues(t *testing.T) {
	fields := map[string]string{
		"authorization": "Bearer super-secret-token",
		"cookie":        "session=top-secret",
		"api_key":       "vt-secret-key",
		"reason":        "upstream rejected Bearer abc123",
		"details":       "client_secret=def456",
		"challenge":     "code_verifier=ghi789",
		"plain":         "ok",
	}

	got := sanitizeAuditFields(fields)

	wantRedacted := []string{"authorization", "cookie", "api_key", "reason", "details", "challenge"}
	for _, key := range wantRedacted {
		if got[key] != "[REDACTED]" {
			t.Fatalf("expected %s redacted, got %q", key, got[key])
		}
	}
	if got["plain"] != "ok" {
		t.Fatalf("expected plain value to survive, got %q", got["plain"])
	}
}

func TestRedactAuditValueRecurses(t *testing.T) {
	input := map[string]interface{}{
		"nested": map[string]interface{}{
			"message": "code_verifier=ghi789",
		},
		"items": []interface{}{
			"Authorization: Bearer abc.def.ghi",
			"safe",
		},
	}

	got := redactAuditValue("audit", input)
	redacted, ok := got.(map[string]interface{})
	if !ok {
		t.Fatalf("expected map result, got %T", got)
	}

	nested := redacted["nested"].(map[string]interface{})
	if nested["message"] != "[REDACTED]" {
		t.Fatalf("expected nested message redacted, got %v", nested["message"])
	}

	items := redacted["items"].([]interface{})
	if items[0] != "[REDACTED]" {
		t.Fatalf("expected item 0 redacted, got %v", items[0])
	}
	if items[1] != "safe" {
		t.Fatalf("expected item 1 preserved, got %v", items[1])
	}
}

func TestIsSensitiveAuditKeyExpandedCoverage(t *testing.T) {
	for _, key := range []string{"authorization", "auth_code", "code_verifier", "code_challenge", "client_secret", "cookie", "session", "password"} {
		if !isSensitiveAuditKey(key) {
			t.Fatalf("expected key %q to be sensitive", key)
		}
	}
	if isSensitiveAuditKey("source") {
		t.Fatal("expected source to remain non-sensitive")
	}
}
