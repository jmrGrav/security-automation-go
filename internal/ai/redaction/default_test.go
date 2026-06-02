package redaction

import (
	"strings"
	"testing"
)

func TestDefaultRedactorRedactsSecretsAndTokens(t *testing.T) {
	input := "Authorization: Bearer abc.def.ghi api_key=secret123 cookie=session123 apiKey=\"secret456\"\n-----BEGIN PRIVATE KEY-----\nline1\nline2\n-----END PRIVATE KEY-----"
	got := DefaultRedactor{}.Redact(input)
	if got.ContainsSecret {
		if got.Redactions == 0 {
			t.Fatalf("expected redactions, got none: %+v", got)
		}
	}
	for _, forbidden := range []string{"secret123", "secret456", "session123", "abc.def.ghi", "PRIVATE KEY", "line1", "line2"} {
		if strings.Contains(got.Text, forbidden) {
			t.Fatalf("redactor leaked %q: %s", forbidden, got.Text)
		}
	}
}
