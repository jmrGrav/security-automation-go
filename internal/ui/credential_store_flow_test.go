package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	aigateway "github.com/jm/security-automation-go/internal/ai/gateway"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/ui/auth"
)

type fakeConfiguredProvider struct {
	name    providers.Name
	enabled bool
}

func (p fakeConfiguredProvider) Name() providers.Name { return p.name }
func (p fakeConfiguredProvider) Enabled() bool        { return p.enabled }
func (p fakeConfiguredProvider) Explain(context.Context, ai.ExplainRequest) (ai.ExplainResponse, error) {
	return ai.ExplainResponse{Provider: string(p.name), Model: "fake"}, nil
}
func (p fakeConfiguredProvider) Quota(context.Context) aiquota.ProviderQuota {
	return aiquota.ProviderQuota{Provider: string(p.name), State: aiquota.Normal}
}

func newCredentialStoreServer(t *testing.T, env map[string]string) (*Server, *sqlite.DB, string) {
	t.Helper()
	dataDir := t.TempDir()
	for k, v := range env {
		t.Setenv(k, v)
	}
	t.Setenv("CF_API_TOKEN", "bootstrap-token")
	t.Setenv("CF_ZONE_ID", "bootstrap-zone")
	t.Setenv("UI_ENABLED", "1")
	t.Setenv("UI_ADDR", "127.0.0.1:9091")
	t.Setenv("UI_SECRET_FILE", filepath.Join(dataDir, "ui-secrets.local"))
	t.Setenv("UI_PROVIDER_STATE_FILE", filepath.Join(dataDir, "ai-providers.env"))
	t.Setenv("STATE_DIR", dataDir)

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config load failed: %v", err)
	}
	cfg.CrowdSec.DecisionsLog = filepath.Join(dataDir, "missing-decisions.log")
	cfg.OpenResty.EventsFile = filepath.Join(dataDir, "missing-events.jsonl")

	db, err := sqlite.New(cfg.StateDir)
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	audit := NewBufferAuditSink()
	aiCfg := ai.FromEnv()
	server, err := NewServer(cfg, Options{
		SecretProvider:      NewFileSecretProvider(cfg.UI.SecretFile),
		CredentialStore:     sqlite.NewCredentialStore(db),
		SetupStore:          sqlite.NewSetupStore(db),
		AuditSink:           audit,
		AIConfig:            aiCfg,
		ValidateCloudflare:  func(context.Context, string, string) error { return nil },
		ValidateAbuseIPDB:   func(context.Context, string) error { return nil },
		ValidateBetterStack: func(context.Context, string) error { return nil },
		AIExplainBuilder:    func(cfg ai.Config) aigateway.Gateway { return aigateway.NewService(cfg, nil, nil, audit) },
		ProviderFactories: map[string]ProviderFactory{
			"openai": func(pc ai.ProviderConfig) providers.Provider {
				return fakeConfiguredProvider{name: providers.OpenAI, enabled: pc.Enabled}
			},
			"anthropic": func(pc ai.ProviderConfig) providers.Provider {
				return fakeConfiguredProvider{name: providers.Anthropic, enabled: pc.Enabled}
			},
			"gemini": func(pc ai.ProviderConfig) providers.Provider {
				return fakeConfiguredProvider{name: providers.Gemini, enabled: pc.Enabled}
			},
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	hash, err := auth.HashPassword("test-password-123!@#")
	if err != nil {
		t.Fatalf("hash bootstrap password: %v", err)
	}
	if err := server.setupStore.SetSetting(context.Background(), "admin_password_hash", hash); err != nil {
		t.Fatalf("seed admin password hash: %v", err)
	}
	if err := server.setupStore.MarkComplete(context.Background()); err != nil {
		t.Fatalf("mark setup complete: %v", err)
	}
	return server, db, cfg.UI.SecretFile
}

func TestSetupWizard_WritesCloudflareTokenIntoCredentialStore(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	cookie := loginCookie(t, srv, "test-password-123!@#")
	srv.mu.Lock()
	srv.sessions[cookie.Value] = time.Now().UTC().Add(time.Hour)
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/setup/step/3", strings.NewReader("cf_token=cf-token-raw&zone_id=zone-123"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK && rr.Code != http.StatusFound {
		t.Fatalf("unexpected status: %d body=%s", rr.Code, rr.Body.String())
	}
	rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "cloudflare.api_token")
	if err != nil {
		t.Fatalf("credential lookup: %v", err)
	}
	if !ok || rec.Value != "cf-token-raw" {
		t.Fatalf("cloudflare token not stored in DB: ok=%v value=%q", ok, rec.Value)
	}
}

func TestSetupWizard_SkipStep4AllowsContinue(t *testing.T) {
	srv, _, _ := newCredentialStoreServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	cookie := loginCookie(t, srv, "test-password-123!@#")
	srv.mu.Lock()
	srv.sessions[cookie.Value] = time.Now().UTC().Add(time.Hour)
	srv.mu.Unlock()
	_ = srv.setupStore.SetCurrentStep(context.Background(), 4)

	req := httptest.NewRequest(http.MethodPost, "/setup/step/4", strings.NewReader("skip=1"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect after skip, got %d body=%s", rr.Code, rr.Body.String())
	}
}

func TestProviderManagement_ReplaceKeyStoresInCredentialStore(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	if err := srv.setupStore.MarkComplete(context.Background()); err != nil {
		t.Fatalf("mark complete: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/key", strings.NewReader("confirm_replace=yes&new_api_key=sk-test-123"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d location=%q body=%s", rr.Code, rr.Header().Get("Location"), rr.Body.String())
	}
	rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "ai.openai.api_key")
	if err != nil {
		t.Fatalf("credential lookup: %v", err)
	}
	if !ok || rec.Value != "sk-test-123" {
		t.Fatalf("openai key not stored in DB: ok=%v value=%q location=%q", ok, rec.Value, rr.Header().Get("Location"))
	}
}

func TestLegacyImportAction_Idempotent(t *testing.T) {
	_, db, _ := newCredentialStoreServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})

	legacyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(legacyDir, "cloudflare_api_token"), []byte("CF_API_TOKEN=cf-legacy-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "openai_api_key"), []byte("openai-legacy-token"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Directly exercise the credential store import path through the same backend used by the UI.
	count, err := sqlite.NewCredentialStore(db).ImportLegacyDir(context.Background(), legacyDir)
	if err != nil {
		t.Fatalf("ImportLegacyDir: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 imports, got %d", count)
	}
	again, err := sqlite.NewCredentialStore(db).ImportLegacyDir(context.Background(), legacyDir)
	if err != nil {
		t.Fatalf("ImportLegacyDir second pass: %v", err)
	}
	if again != 0 {
		t.Fatalf("expected idempotent import, got %d", again)
	}
}

func TestLegacyImportAction_ImportsViaUI(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	legacyDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(legacyDir, "cloudflare_api_token"), []byte("CF_API_TOKEN=cf-legacy-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyDir, "abuseipdb_api_key"), []byte("ABUSEIPDB_KEY=abuse-legacy-token"), 0o600); err != nil {
		t.Fatal(err)
	}
	origLegacyDir := legacySecretsDirPath
	legacySecretsDirPath = legacyDir
	defer func() { legacySecretsDirPath = origLegacyDir }()

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodPost, "/admin/providers/import-legacy", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
		t.Fatalf("expected redirect, got %d body=%s", rr.Code, rr.Body.String())
	}
	if rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "cloudflare.api_token"); err != nil {
		t.Fatalf("cloudflare lookup: %v", err)
	} else if !ok || rec.Value != "cf-legacy-token" {
		t.Fatalf("cloudflare token not imported: ok=%v value=%q", ok, rec.Value)
	}
	if rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "abuseipdb.api_key"); err != nil {
		t.Fatalf("abuse lookup: %v", err)
	} else if !ok || rec.Value != "abuse-legacy-token" {
		t.Fatalf("abuse key not imported: ok=%v value=%q", ok, rec.Value)
	}
}
