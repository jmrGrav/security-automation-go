package redaction

import (
	"regexp"
)

var (
	// BearerRe matches common Bearer token formats.
	BearerRe = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._\-~+/=]+`)
	// JWTRe matches potential JSON Web Tokens.
	JWTRe = regexp.MustCompile(`\b[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	// KeyValueRe matches common sensitive key-value patterns in strings (e.g., api_key=...).
	KeyValueRe = regexp.MustCompile(`(?i)\b(api[_-]?key|x-api-key|access[_-]?token|refresh[_-]?token|id[_-]?token|client[_-]?secret|code[_-]?verifier|code[_-]?challenge|auth[_-]?code|token|secret|password|credential|cookie|session[_-]?id|authorization)\b\s*[:=]\s*(?:"[^"]*"|'[^']*'|[^\s,;"]+)`)
	// PEMRe matches PEM-encoded blocks (keys, certs).
	PEMRe = regexp.MustCompile(`(?s)-----BEGIN [^-]+-----.*?-----END [^-]+-----`)
)

// DefaultPatterns returns the list of regexes used for redaction across the project.
func DefaultPatterns() []*regexp.Regexp {
	return []*regexp.Regexp{
		BearerRe,
		JWTRe,
		KeyValueRe,
		PEMRe,
	}
}
