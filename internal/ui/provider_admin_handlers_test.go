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
	rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "abuseipdb.api_key")
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

func TestNormalizeAIConfigRestoresDefaultModels(t *testing.T) {
	cfg := ai.Config{
		OpenAI:    ai.ProviderConfig{Enabled: true, Model: ""},
		Anthropic: ai.ProviderConfig{Enabled: true, Model: ""},
		Gemini:    ai.ProviderConfig{Enabled: true, Model: ""},
	}
	got := normalizeAIConfig(cfg)
	if got.OpenAI.Model != ai.DefaultOpenAIModel {
		t.Errorf("openai: want %q, got %q", ai.DefaultOpenAIModel, got.OpenAI.Model)
	}
	if got.Anthropic.Model != ai.DefaultAnthropicModel {
		t.Errorf("anthropic: want %q, got %q", ai.DefaultAnthropicModel, got.Anthropic.Model)
	}
	if got.Gemini.Model != ai.DefaultGeminiModel {
		t.Errorf("gemini: want %q, got %q", ai.DefaultGeminiModel, got.Gemini.Model)
	}

	// Disabled providers must not get a model injected.
	cfgDisabled := ai.Config{
		OpenAI:    ai.ProviderConfig{Enabled: false, Model: ""},
		Anthropic: ai.ProviderConfig{Enabled: false, Model: ""},
		Gemini:    ai.ProviderConfig{Enabled: false, Model: ""},
	}
	gotDisabled := normalizeAIConfig(cfgDisabled)
	if gotDisabled.OpenAI.Model != "" || gotDisabled.Anthropic.Model != "" || gotDisabled.Gemini.Model != "" {
		t.Errorf("disabled providers must not get default models injected: %+v", gotDisabled)
	}

	// Explicitly-set models must not be overwritten.
	cfgWithModel := ai.Config{
		OpenAI:    ai.ProviderConfig{Enabled: true, Model: "gpt-3.5-turbo"},
		Anthropic: ai.ProviderConfig{Enabled: true, Model: "claude-2"},
		Gemini:    ai.ProviderConfig{Enabled: true, Model: "gemini-pro"},
	}
	gotWithModel := normalizeAIConfig(cfgWithModel)
	if gotWithModel.OpenAI.Model != "gpt-3.5-turbo" {
		t.Errorf("openai: explicit model should not be overwritten, got %q", gotWithModel.OpenAI.Model)
	}
}

// TestNonAIProviderReplaceKeyUpdatesDisplay verifies that after a Replace Key POST,
// the /providers page immediately shows "CONFIGURED" for the provider without restart.
func TestNonAIProviderReplaceKeyUpdatesDisplay(t *testing.T) {
	for _, tc := range []struct {
		slug    string
		credKey string
	}{
		{"spamhaus", "spamhaus.api_key"},
		{"virustotal", "virustotal.api_key"},
		{"abuseipdb", "abuseipdb.api_key"},
	} {
		t.Run(tc.slug, func(t *testing.T) {
			srv, db, _ := newCredentialStoreServer(t, nil)
			cookie := loginCookie(t, srv, "test-password-123!@#")
			csrf := srv.csrfTokenFor(cookie.Value)

			// POST Replace Key
			body := "confirm_replace=yes&new_api_key=placeholder-" + tc.slug
			req := httptest.NewRequest(http.MethodPost, "/admin/providers/"+tc.slug+"/key", strings.NewReader(body))
			req.AddCookie(cookie)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-CSRF-Token", csrf)
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusSeeOther {
				t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
			}

			// Verify written under the dotted key name
			rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), tc.credKey)
			if err != nil {
				t.Fatalf("load credential: %v", err)
			}
			if !ok || rec.Value != "placeholder-"+tc.slug {
				t.Fatalf("credential not stored under %q: ok=%v value=%q", tc.credKey, ok, rec.Value)
			}

			// Verify GET /providers now shows CONFIGURED for this provider
			req2 := httptest.NewRequest(http.MethodGet, "/providers", nil)
			req2.AddCookie(cookie)
			rr2 := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr2, req2)
			if rr2.Code != http.StatusOK {
				t.Fatalf("GET /providers: %d", rr2.Code)
			}
			html := rr2.Body.String()
			if !strings.Contains(strings.ToUpper(html), "CONFIGURED") {
				t.Errorf("%s: /providers page must show CONFIGURED after Replace Key", tc.slug)
			}
			if strings.Contains(html, "placeholder-"+tc.slug) {
				t.Errorf("%s: raw key must never appear in /providers HTML", tc.slug)
			}
		})
	}
}

// TestNonAIProviderKeyNeverLeaksInHTML verifies that the raw key value is never rendered,
// only a masked representation.
func TestNonAIProviderKeyNeverLeaksInHTML(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, nil)
	// Seed a key directly into the credential store
	const syntheticKey = "placeholder-spamhaus-value"
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "spamhaus.api_key", syntheticKey, true); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	html := rr.Body.String()
	if strings.Contains(html, syntheticKey) {
		t.Error("raw Spamhaus API key must never appear in /providers HTML")
	}
	if !strings.Contains(strings.ToUpper(html), "CONFIGURED") {
		t.Error("/providers page must show CONFIGURED for Spamhaus after key is seeded")
	}
}
