package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestProviderHealthCenter_RendersConfiguredMissingAndMasksSecrets(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_ENABLED": "true",
		"AI_PROVIDER_OPENAI_MODEL":   "gpt-4.1-mini",
	})
	store := sqlite.NewCredentialStore(db)
	if err := store.Set(context.Background(), "ai.openai.api_key", "openai-secret", true); err != nil {
		t.Fatalf("seed openai credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"AI Providers",
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
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_ENABLED": "true",
		"AI_PROVIDER_OPENAI_MODEL":   "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "openai-secret", true); err != nil {
		t.Fatalf("seed openai credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")

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
		"credential store",
		"provider disabled by operator",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("providers page missing %q: %s", want, body)
		}
	}
}

func TestProviderHealthCenter_RendersObservedQuotaState(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_ANTHROPIC_MODEL": "claude-3-5-sonnet-latest",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.anthropic.api_key", "anthropic-secret", true); err != nil {
		t.Fatalf("seed anthropic credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{"Anthropic", "credential store", "last test status", "validation"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected provider field %q in body: %s", want, body)
		}
	}
}

func TestProviderHealthCenter_RendersQuotaOverviewAndQuotaDetails(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_ENABLED": "true",
		"AI_PROVIDER_OPENAI_MODEL":   "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "openai-secret", true); err != nil {
		t.Fatalf("seed openai credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := strings.ToLower(rr.Body.String())
	for _, want := range []string{
		"ai providers",
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
