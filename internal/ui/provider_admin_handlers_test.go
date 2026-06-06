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
	secretDir := t.TempDir()
	openaiKey := filepath.Join(secretDir, "openai_api_key")
	srv, audit, secretPath := newTestServer(t, map[string]string{
		"UI_SECRET":                          "ui-secret-value",
		"AI_PROVIDER_OPENAI_API_KEY_FILE":    openaiKey,
		"AI_PROVIDER_OPENAI_MODEL":           "gpt-4.1-mini",
		"AI_PROVIDER_ANTHROPIC_API_KEY_FILE": filepath.Join(secretDir, "anthropic_api_key"),
		"AI_PROVIDER_GEMINI_API_KEY_FILE":    filepath.Join(secretDir, "gemini_api_key"),
	})
	stateFile := filepath.Join(filepath.Dir(secretPath), "ai-providers.env")
	cookie := loginCookie(t, srv, "ui-secret-value")
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
	info, err := os.Stat(openaiKey)
	if err != nil {
		t.Fatalf("secret file missing: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected 0600 secret file, got %#o", got)
	}
	data, err := os.ReadFile(openaiKey)
	if err != nil {
		t.Fatalf("read secret file: %v", err)
	}
	if strings.TrimSpace(string(data)) != "super-secret-token" {
		t.Fatalf("secret file not written correctly: %q", string(data))
	}
	state, ok, err := loadAIProviderState(stateFile)
	if err != nil {
		t.Fatalf("load state file: %v", err)
	}
	if ok {
		t.Fatalf("replace key must not write provider state file: %#v", state)
	}
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		t.Fatalf("provider state file should remain absent, got err=%v", err)
	}
	if strings.Contains(strings.ToLower(audit.String()), "super-secret-token") {
		t.Fatalf("audit leaked secret: %s", audit.String())
	}
}

func TestProviderManagementRequiresAuthAndCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "ui-secret-value",
	})

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/key", strings.NewReader("confirm_replace=yes&new_api_key=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected auth redirect, got %d", rr.Code)
	}

	cookie := loginCookie(t, srv, "ui-secret-value")
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
	secretDir := t.TempDir()
	srv, _, secretPath := newTestServer(t, map[string]string{
		"UI_SECRET":                       "ui-secret-value",
		"AI_PROVIDER_OPENAI_API_KEY_FILE": filepath.Join(secretDir, "openai_api_key"),
		"AI_PROVIDER_OPENAI_MODEL":        "gpt-4.1-mini",
	})
	stateFile := filepath.Join(filepath.Dir(secretPath), "ai-providers.env")
	cookie := loginCookie(t, srv, "ui-secret-value")

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
	for _, want := range []string{"impossible to write the secret", "sudo install -d -m 700 -o root -g root /etc/security-automation-go/secrets", "openai_api_key"} {
		if !strings.Contains(body, want) {
			t.Fatalf("enable error missing %q: %s", want, body)
		}
	}
	state, _, err := loadAIProviderState(stateFile)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.OpenAI.Enabled {
		t.Fatal("provider must remain disabled when secret is missing")
	}
}

func TestProviderManagementTestProviderUsesStubAndRedacts(t *testing.T) {
	secretDir := t.TempDir()
	openaiKey := filepath.Join(secretDir, "openai_api_key")
	srv, audit, secretPath := newTestServer(t, map[string]string{
		"UI_SECRET":                       "ui-secret-value",
		"AI_PROVIDER_OPENAI_API_KEY_FILE": openaiKey,
		"AI_PROVIDER_OPENAI_ENABLED":      "true",
		"AI_PROVIDER_OPENAI_MODEL":        "gpt-4.1-mini",
	})
	stateFile := filepath.Join(filepath.Dir(secretPath), "ai-providers.env")
	if err := os.WriteFile(openaiKey, []byte("test-secret"), 0o600); err != nil {
		t.Fatalf("write secret: %v", err)
	}
	srv.providerFactories["openai"] = func(pc ai.ProviderConfig) providers.Provider {
		return fakeProvider{name: providers.OpenAI, err: &providers.Error{Provider: providers.OpenAI, StatusCode: http.StatusTooManyRequests, Reason: "rate limited"}}
	}
	cookie := loginCookie(t, srv, "ui-secret-value")
	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/test", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after test, got %d", rr.Code)
	}
	state, _, err := loadAIProviderState(stateFile)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if state.OpenAI.LastTestStatus != providerTestRateLimited {
		t.Fatalf("expected rate limited test status, got %#v", state.OpenAI)
	}
	if state.OpenAI.LastTestLatencyMS < 0 {
		t.Fatalf("invalid latency stored: %#v", state.OpenAI)
	}
	for _, forbidden := range []string{"test-secret", "rate limited"} {
		if strings.Contains(strings.ToLower(audit.String()), strings.ToLower(forbidden)) {
			t.Fatalf("audit leaked %q: %s", forbidden, audit.String())
		}
	}
}
