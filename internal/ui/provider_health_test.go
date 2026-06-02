package ui

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestProviderHealthCenter_RendersConfiguredMissingAndMasksSecrets(t *testing.T) {
	secretDir := t.TempDir()
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET":                          "ui-secret-value",
		"AI_PROVIDER_OPENAI_ENABLED":         "true",
		"AI_PROVIDER_OPENAI_MODEL":           "gpt-4.1-mini",
		"AI_PROVIDER_OPENAI_API_KEY_FILE":    filepath.Join(secretDir, "openai_api_key"),
		"AI_PROVIDER_ANTHROPIC_API_KEY_FILE": filepath.Join(secretDir, "anthropic_api_key"),
		"AI_PROVIDER_GEMINI_API_KEY_FILE":    filepath.Join(secretDir, "gemini_api_key"),
	})
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"Provider Management",
		"OpenAI",
		"Anthropic",
		"Gemini",
		"Replace Key",
		"Test Provider",
		"Enable Provider",
		"MISSING_SECRET",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("providers page missing %q: %s", want, body)
		}
	}
	for _, secret := range []string{"ui-secret-value", "spamhaus-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("providers page leaked secret %q: %s", secret, body)
		}
	}
}

func TestProviderHealthCenter_RendersOperationalFieldsAndQuotaFallback(t *testing.T) {
	secretDir := t.TempDir()
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET":                       "ui-secret-value",
		"AI_PROVIDER_OPENAI_ENABLED":      "true",
		"AI_PROVIDER_OPENAI_MODEL":        "gpt-4.1-mini",
		"AI_PROVIDER_OPENAI_API_KEY_FILE": filepath.Join(secretDir, "openai_api_key"),
	})
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"last test at",
		"last test status",
		"last test latency",
		"last error code",
		"validation",
		"secret file",
		"provider disabled by operator",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("providers page missing %q: %s", want, body)
		}
	}
}

func TestProviderHealthCenter_RendersObservedQuotaState(t *testing.T) {
	secretDir := t.TempDir()
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET":                          "ui-secret-value",
		"AI_PROVIDER_ANTHROPIC_MODEL":        "claude-3-5-sonnet-latest",
		"AI_PROVIDER_ANTHROPIC_API_KEY_FILE": filepath.Join(secretDir, "anthropic_api_key"),
	})
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{"Anthropic", "secret file", "last test status", "validation"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected provider field %q in body: %s", want, body)
		}
	}
}

func TestProviderHealthCenter_RendersQuotaOverviewAndQuotaDetails(t *testing.T) {
	secretDir := t.TempDir()
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET":                       "ui-secret-value",
		"AI_PROVIDER_OPENAI_ENABLED":      "true",
		"AI_PROVIDER_OPENAI_MODEL":        "gpt-4.1-mini",
		"AI_PROVIDER_OPENAI_API_KEY_FILE": filepath.Join(secretDir, "openai_api_key"),
	})
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := strings.ToLower(rr.Body.String())
	for _, want := range []string{
		"provider management",
		"replace key",
		"test provider",
		"enable provider",
		"openai",
		"anthropic",
		"gemini",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("providers page missing %q: %s", want, rr.Body.String())
		}
	}
}
