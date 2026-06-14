package ui

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"

	"github.com/jm/security-automation-go/internal/ai/providers"
)

func TestProviderTestOutcomeMapsCommonProviderFailures(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "authentication failed",
			err:  &providers.Error{StatusCode: http.StatusForbidden, Reason: "authentication failed"},
			want: "AUTH_FAILED",
		},
		{
			name: "invalid api key",
			err:  &providers.Error{StatusCode: http.StatusUnauthorized, Reason: "invalid api key"},
			want: "INVALID_API_KEY",
		},
		{
			name: "quota exceeded",
			err:  &providers.Error{StatusCode: http.StatusTooManyRequests, Reason: "quota exhausted"},
			want: "QUOTA_EXCEEDED",
		},
		{
			name: "rate limited",
			err:  &providers.Error{StatusCode: http.StatusTooManyRequests, Reason: "rate limited"},
			want: "RATE_LIMITED",
		},
		{
			name: "timeout",
			err:  context.DeadlineExceeded,
			want: "TIMEOUT",
		},
		{
			name: "dns failure",
			err:  &providers.Error{Err: &net.DNSError{Err: "no such host", Name: "api.example.invalid"}},
			want: "DNS_FAILURE",
		},
		{
			name: "tls failure",
			err:  errors.New("x509: certificate signed by unknown authority"),
			want: "TLS_FAILURE",
		},
		{
			name: "provider disabled by operator",
			err:  &providers.Error{Reason: "provider disabled"},
			want: "DISABLED_BY_OPERATOR",
		},
		{
			name: "unsupported model",
			err:  &providers.Error{StatusCode: http.StatusBadRequest, Reason: "unsupported model"},
			want: "UNSUPPORTED_MODEL",
		},
		{
			name: "http status fallback",
			err:  &providers.Error{StatusCode: http.StatusTeapot, Reason: "unexpected"},
			want: "HTTP_418",
		},
		{
			name: "unknown fallback",
			err:  errors.New("unexpected provider failure"),
			want: "TEST_FAILED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotStatus, gotCode := providerTestOutcome(tc.err)
			if gotStatus != tc.want {
				t.Fatalf("status: want %q, got %q", tc.want, gotStatus)
			}
			if gotCode != tc.want {
				t.Fatalf("code: want %q, got %q", tc.want, gotCode)
			}
		})
	}
}

func TestProviderStatusAndDisplayUseShortDiagnostics(t *testing.T) {
	if got := providerManagementStatus(true, "configured", "AUTH_FAILED"); got != "AUTH_FAILED" {
		t.Fatalf("expected auth failure badge to preserve diagnostic, got %q", got)
	}
	if got := providerManagementStatus(true, "configured", "TEST_FAILED"); got != "TEST_FAILED" {
		t.Fatalf("expected fallback badge to preserve diagnostic, got %q", got)
	}
	if got := providerManagementStatus(false, "configured", "AUTH_FAILED"); got != providerStatusDisabled {
		t.Fatalf("disabled providers must stay disabled, got %q", got)
	}

	displayCases := map[string]string{
		"AUTH_FAILED":          "authentication failed",
		"INVALID_API_KEY":      "invalid API key",
		"QUOTA_EXCEEDED":       "quota exceeded",
		"RATE_LIMITED":         "rate limited",
		"TIMEOUT":              "timeout",
		"DNS_FAILURE":          "DNS failure",
		"TLS_FAILURE":          "TLS failure",
		"DISABLED_BY_OPERATOR": "provider disabled by operator",
		"UNSUPPORTED_MODEL":    "unsupported model",
		"HTTP_403":             "http 403",
		"TEST_FAILED":          "provider returned empty error",
	}

	for code, want := range displayCases {
		t.Run(code, func(t *testing.T) {
			if got := displayProviderTestStatus(code); got != want {
				t.Fatalf("displayProviderTestStatus(%q): want %q, got %q", code, want, got)
			}
			if got := displayProviderErrorCode(code); got != want {
				t.Fatalf("displayProviderErrorCode(%q): want %q, got %q", code, want, got)
			}
		})
	}
}
