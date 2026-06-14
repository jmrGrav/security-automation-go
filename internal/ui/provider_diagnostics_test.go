package ui

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
)

func TestProviderStatusDistinguishesDisabledAndMissingSecrets(t *testing.T) {
	if got := providerStatus(false, false); got != "disabled by operator" {
		t.Fatalf("disabled+missing should be disabled by operator, got %q", got)
	}
	if got := providerStatus(false, true); got != "configured / disabled" {
		t.Fatalf("disabled+configured should show configured / disabled, got %q", got)
	}
	if got := providerStatus(true, false); got != "missing secret" {
		t.Fatalf("enabled+missing should show missing secret, got %q", got)
	}
}

func TestProviderManagementEntryMarksDisabledProvidersWithoutSecretAsNotConfigured(t *testing.T) {
	got := providerManagementEntry(AIProviderOpenAI, ai.ProviderConfig{Enabled: false, Model: "gpt-4.1-mini"}, false, AIProviderRecord{})
	if got.Status != providerStatusDisabled {
		t.Fatalf("expected disabled status, got %q", got.Status)
	}
	if got.SecretState != "not configured" {
		t.Fatalf("disabled provider should be marked not configured: %+v", got)
	}
	if got.ValidationMessage != "provider disabled by operator" {
		t.Fatalf("expected disabled validation message, got %q", got.ValidationMessage)
	}
}

func TestProviderTestOutcomeClassifiesProviderErrors(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		status   string
		errorCod string
	}{
		{
			name:     "disabled",
			err:      &providers.Error{Reason: "provider disabled"},
			status:   providerTestDisabledByOperator,
			errorCod: providerTestDisabledByOperator,
		},
		{
			name:     "auth",
			err:      &providers.Error{StatusCode: http.StatusUnauthorized, Reason: "unauthorized"},
			status:   providerTestAuthFailed,
			errorCod: providerTestAuthFailed,
		},
		{
			name:     "rate",
			err:      &providers.Error{StatusCode: http.StatusTooManyRequests, Reason: "rate limited"},
			status:   providerTestRateLimited,
			errorCod: providerTestRateLimited,
		},
		{
			name:     "timeout",
			err:      context.DeadlineExceeded,
			status:   providerTestTimeout,
			errorCod: providerTestTimeout,
		},
		{
			name:     "fallback",
			err:      errors.New("opaque failure"),
			status:   providerTestUnknownError,
			errorCod: providerTestUnknownError,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			status, code := providerTestOutcome(tc.err)
			if status != tc.status || code != tc.errorCod {
				t.Fatalf("unexpected classification: status=%q code=%q", status, code)
			}
		})
	}
}

func TestDisplayProviderOutputsHideUnknownError(t *testing.T) {
	if got := displayProviderTestStatus(providerTestUnknownError); strings.Contains(strings.ToLower(got), "unknown") {
		t.Fatalf("unknown test status should not be shown verbatim: %q", got)
	}
	if got := displayProviderErrorCode(providerTestUnknownError); strings.Contains(strings.ToLower(got), "unknown") {
		t.Fatalf("unknown error code should not be shown verbatim: %q", got)
	}
}
