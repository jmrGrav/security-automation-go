package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

type fakeProvider struct {
	name providers.Name
	err  error
}

func (p fakeProvider) Name() providers.Name { return p.name }
func (p fakeProvider) Enabled() bool        { return true }
func (p fakeProvider) Explain(context.Context, ai.ExplainRequest) (ai.ExplainResponse, error) {
	return ai.ExplainResponse{Provider: string(p.name), Model: "fake-model", Explanation: "fake"}, p.err
}
func (p fakeProvider) Quota(context.Context) aiquota.ProviderQuota {
	return aiquota.ProviderQuota{Provider: string(p.name), State: aiquota.Normal}
}

func TestProviderManagementReplaceKeyWrites0600AndKeepsDisabled(t *testing.T) {
	srv, db, secretPath := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	legacyFile := filepath.Join(filepath.Dir(secretPath), "openai_api_key")
	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/key", strings.NewReader("confirm_replace=yes&new_api_key=super-secret-token"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
	}
	rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "ai.openai.api_key")
	if err != nil {
		t.Fatalf("load credential: %v", err)
	}
	if !ok || rec.Value != "super-secret-token" {
		t.Fatalf("credential not stored in SQLite: ok=%v value=%q", ok, rec.Value)
	}
	if audit, ok := srv.audit.(*BufferAuditSink); ok {
		if strings.Contains(strings.ToLower(audit.String()), "super-secret-token") {
			t.Fatalf("audit leaked secret: %s", audit.String())
		}
	}
	if _, err := os.Stat(legacyFile); !os.IsNotExist(err) {
		t.Fatalf("legacy secret file should not be written, got err=%v", err)
	}
}

func TestProviderManagementRequiresAuthAndCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/key", strings.NewReader("confirm_replace=yes&new_api_key=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected auth redirect, got %d", rr.Code)
	}

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req = httptest.NewRequest(http.MethodPost, "/admin/providers/openai/key", strings.NewReader("confirm_replace=yes&new_api_key=secret"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected csrf rejection, got %d", rr.Code)
	}
}

func TestProviderManagementEnableRequiresReadableSecret(t *testing.T) {
	srv, _, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/enable", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected enable refusal, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"credential not configured in SQLite", "OpenAI"} {
		if !strings.Contains(body, want) {
			t.Fatalf("enable error missing %q: %s", want, body)
		}
	}
}

func TestUnifiedProvidersPageShowsAllNineProviders(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"OpenAI", "Anthropic", "Gemini",
		"AbuseIPDB", "Spamhaus", "VirusTotal",
		"Cloudflare", "CrowdSec", "BetterStack",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("unified providers page missing %q", want)
		}
	}
}

func TestNonAIProviderReplaceKeyWritesToCredentialStore(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/abuseipdb/key", strings.NewReader("confirm_replace=yes&new_api_key=abuse-test-key-xyz"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
	}
	rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "ABUSEIPDB_KEY")
	if err != nil {
		t.Fatalf("load credential: %v", err)
	}
	if !ok || rec.Value != "abuse-test-key-xyz" {
		t.Fatalf("credential not stored: ok=%v value=%q", ok, rec.Value)
	}
}

func TestAIProviderStatePersistsToSQLiteAndSurvivesReload(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "test-key", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/enable", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after enable, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify persisted to SQLite
	store := sqlite.NewSetupStore(db)
	v, ok, err := store.GetSetting(context.Background(), "ai.openai.enabled")
	if err != nil {
		t.Fatalf("read sqlite: %v", err)
	}
	if !ok || v != "true" {
		t.Fatalf("expected ai.openai.enabled=true in sqlite, got ok=%v v=%q", ok, v)
	}

	// Verify the view reflects the persisted state
	req2 := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req2.AddCookie(cookie)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("providers page %d: %s", rr2.Code, rr2.Body.String())
	}
	if !strings.Contains(rr2.Body.String(), "ENABLED") {
		t.Fatalf("providers page does not show ENABLED after sqlite-persisted enable: %s", rr2.Body.String())
	}
}

func TestProviderManagementTestProviderUsesStubAndRedacts(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_ENABLED": "true",
		"AI_PROVIDER_OPENAI_MODEL":   "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "test-secret", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	srv.providerFactories["openai"] = func(pc ai.ProviderConfig) providers.Provider {
		return fakeProvider{name: providers.OpenAI, err: &providers.Error{Provider: providers.OpenAI, StatusCode: http.StatusTooManyRequests, Reason: "rate limited"}}
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/test", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after test, got %d", rr.Code)
	}
	state, _, err := loadAIProviderStateFromStore(context.Background(), sqlite.NewSetupStore(db))
	if err != nil {
		t.Fatalf("load state from sqlite: %v", err)
	}
	if state.OpenAI.LastTestStatus != providerTestRateLimited {
		t.Fatalf("expected rate limited test status, got %#v", state.OpenAI)
	}
	if state.OpenAI.LastTestLatencyMS < 0 {
		t.Fatalf("invalid latency stored: %#v", state.OpenAI)
	}
	if audit, ok := srv.audit.(*BufferAuditSink); ok {
		for _, forbidden := range []string{"test-secret", "rate limited"} {
			if strings.Contains(strings.ToLower(audit.String()), strings.ToLower(forbidden)) {
				t.Fatalf("audit leaked %q: %s", forbidden, audit.String())
			}
		}
	}
}
