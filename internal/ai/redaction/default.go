package redaction

import (
	"strings"

	shared "github.com/jm/security-automation-go/internal/security/redaction"
)

// DefaultRedactor redacts common secret shapes from prompt/context text.
type DefaultRedactor struct{}

// Redact replaces obvious secrets and tokens with placeholders.
func (DefaultRedactor) Redact(input string) Result {
	out := input
	count := 0
	patterns := shared.DefaultPatterns()

	for _, re := range patterns {
		matches := re.FindAllStringIndex(out, -1)
		if len(matches) == 0 {
			continue
		}
		count += len(matches)
		// Special handling for KeyValueRe to preserve the key but redact the value
		if re == shared.KeyValueRe {
			out = re.ReplaceAllString(out, "$1=[redacted]")
		} else {
			out = re.ReplaceAllString(out, "[redacted]")
		}
	}

	out = strings.ReplaceAll(out, "Authorization: ", "Authorization: [redacted] ")
	return Result{Text: out, Redactions: count, ContainsSecret: count > 0}
}
