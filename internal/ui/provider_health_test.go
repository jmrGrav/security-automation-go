package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestProviderHealthCenter_RendersDisabledProvidersAsNotConfiguredAndMasksSecrets(t *testing.T) {
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
		"provider-actions",
		"action-button",
		"Update Key",
		"Test Now",
		"Enable Provider",
		"NOT CONFIGURED",
		"provider disabled by operator",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("providers page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "MISSING_SECRET") {
		t.Fatalf("disabled providers should not be rendered as missing secret: %s", body)
	}
	for _, secret := range []string{"ui-secret-value", "spamhaus-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("providers page leaked secret %q: %s", secret, body)
		}
	}
}

func TestUnifiedProvidersPageRendersCompactActionRail(t *testing.T) {
	view := UnifiedProvidersView{
		AI: AIProviderManagementView{
			Providers: []AIProviderManagementEntry{{
				Name:              "OpenAI",
				Status:            providerStatusReady,
				Model:             "gpt-4.1-mini",
				Enabled:           true,
				SecretState:       "configured",
				SecretPathDisplay: "SQLite credential store",
				LastTestAt:        "2026-06-12T10:00:00Z",
				LastTestStatus:    "ready",
				LastTestLatencyMS: "120ms",
				LastErrorCode:     "none",
				ValidationMessage: "credential present and configuration valid",
			}},
		},
	}

	comp := UnifiedProvidersPage(view, "csrf-token")
	var buf strings.Builder
	if err := comp.Render(context.Background(), &buf); err != nil {
		t.Fatalf("render unified providers page: %v", err)
	}
	body := buf.String()
	for _, want := range []string{
		"data-live-shell=\"providers\"",
		"operator-live.js",
		"providers-live.js",
		"Test All",
		"provider-actions",
		"provider-key-form",
		"action-button",
		"Update Key",
		"Test Now",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in provider card HTML: %s", want, body)
		}
	}
}

func TestRenderV2ProvidersPageUsesV2ShellAndProviderStates(t *testing.T) {
	view := UnifiedProvidersView{
		AI: AIProviderManagementView{
			Providers: []AIProviderManagementEntry{
				{
					Name:              "OpenAI",
					Status:            providerStatusReady,
					Model:             "gpt-4.1-mini",
					ConfiguredState:   "configured",
					EnabledState:      "enabled",
					Enabled:           true,
					SecretState:       "configured",
					HealthyState:      "healthy",
					SecretPathDisplay: "SQLite credential store",
					LastTestAt:        "2026-06-12T10:00:00Z",
					LastSuccessAt:     "2026-06-12T10:00:00Z",
					LastFailureAt:     "never",
					LastTestStatus:    providerTestReady,
					LastTestLatencyMS: "120ms",
					LastErrorCode:     "",
					ValidationMessage: "credential present and configuration valid",
				},
				{
					Name:              "Anthropic",
					Status:            providerStatusMissingSecret,
					Model:             "claude-3-5-sonnet-latest",
					ConfiguredState:   "missing",
					EnabledState:      "enabled",
					Enabled:           true,
					SecretState:       providerStatusMissingSecret,
					HealthyState:      "error",
					SecretPathDisplay: "SQLite credential store",
					LastTestAt:        "never",
					LastTestStatus:    providerStatusMissingSecret,
					LastTestLatencyMS: "n/a",
					LastErrorCode:     providerStatusMissingSecret,
					ValidationMessage: "credential missing from SQLite",
				},
				{
					Name:              "Gemini",
					Status:            providerStatusDisabled,
					Model:             "gemini-1.5-flash",
					ConfiguredState:   "missing",
					EnabledState:      "disabled",
					SecretState:       "not configured",
					HealthyState:      "disabled",
					SecretPathDisplay: "SQLite credential store",
					LastTestAt:        "never",
					LastTestStatus:    providerTestDisabledByOperator,
					LastTestLatencyMS: "n/a",
					LastErrorCode:     "",
					ValidationMessage: "provider disabled by operator",
				},
			},
		},
		NonAI: []NonAIProviderEntry{{
			Name:             "AbuseIPDB",
			Category:         "reporting",
			Configured:       true,
			Enabled:          true,
			Healthy:          false,
			MaskedKey:        "ab…redacted",
			HasKeyManagement: true,
			ConfiguredState:  "configured",
			EnabledState:     "enabled",
			HealthyState:     "warning",
			LastTestAt:       "2026-06-12T10:00:00Z",
			LastLatencyMS:    "240ms",
			LastErrorCode:    providerTestRateLimited,
			Status:           "rate limited",
		}},
	}

	body := renderV2ProvidersPage(view, "csrf-token")

	for _, want := range []string{
		"Providers · Operator Console",
		`href="/v2/providers"`,
		`data-live-shell="providers"`,
		`data-refresh-url="/v2/providers"`,
		"Provider mesh",
		"AI Providers",
		"Reporting &amp; Enrichment",
		"credential missing from SQLite",
		"provider disabled by operator",
		"rate limited",
		`data-ts="`,
		"/v2/static/providers-live.js",
		"Copy diagnostic JSON",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("v2 providers page missing %q: %s", want, body)
		}
	}
	for _, secret := range []string{"sk-", "openai-secret", "anthropic-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("v2 providers page leaked secret %q: %s", secret, body)
		}
	}
}

func TestServer_V2ProvidersRouteUsesV2Shell(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/v2/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected /v2/providers 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`href="/v2/providers"`,
		`data-live-shell="providers"`,
		`data-refresh-url="/v2/providers"`,
		"/v2/static/providers-live.js",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("/v2/providers missing %q: %s", want, body)
		}
	}
}

func TestProvidersLiveScriptServed(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/static/providers-live.js", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected providers live script, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"data-live-shell", "refreshUrl", "data-live-provider-form"} {
		if !strings.Contains(body, want) {
			t.Fatalf("providers live script missing %q: %s", want, body)
		}
	}
}

func TestV2ProvidersLiveScriptServed(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/v2/static/providers-live.js", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected v2 providers live script, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"refreshUrl", "refreshURL", "Copy diagnostic JSON", "Diagnostic JSON copied"} {
		if !strings.Contains(body, want) {
			t.Fatalf("v2 providers live script missing %q: %s", want, body)
		}
	}
}

func TestV2PaletteRoutesOperatorQueries(t *testing.T) {
	script := paletteJS
	for _, want := range []string{
		"routeQuery",
		"/v2/investigate?q=",
		"/v2/timeline",
		"/v2/providers",
		"/v2/health",
		"/v2/audit",
		"AS",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("v2 palette script missing routing artifact %q: %s", want, script)
		}
	}
}

func TestRenderV2DashboardTellsOperatorStory(t *testing.T) {
	view := DashboardConsoleView{
		HealthyCount: 2,
		Statuses: []StatusItem{
			{Label: "Runtime", Level: "healthy", Detail: "ui active"},
			{Label: "SQLite", Level: "healthy", Detail: "schema ready"},
			{Label: "Cloudflare", Level: "warning", Detail: "dry-run"},
		},
		AIProviders: []AIProviderDashboardView{{Name: "OpenAI", Status: "ready", Model: "gpt-4.1-mini"}},
		CommandCenter: DashboardCommandCenterView{
			Health: DashboardHealthScoreView{Score: 82, Level: "degraded", Summary: "82% platform health"},
			Threat: DashboardThreatView{
				TotalEvents: 3,
				Countries:   []DashboardThreatCountryView{{Country: "United States", Count: 3, Level: "warning"}},
				Campaigns:   []DashboardThreatCampaignView{{Scenario: "http-probe", Source: "cloudflare_waf", Country: "United States", Count: 3, Level: "warning"}},
			},
			Activity: DashboardActivityFeedView{Items: []DashboardActivityItemView{{
				Timestamp: "2026-06-24T00:00:00Z",
				Severity:  "warning",
				Title:     "report_pending",
				Detail:    "203.0.113.10 · cloudflare_waf · US",
				Href:      "/evidence/ev1",
			}}},
			TimeWindow: DashboardTimeWindowView{Options: []DashboardTimeWindowOption{{Label: "24h", Value: "24h", Active: true}}},
		},
		ReportedTotal: 1,
	}

	out := renderV2Dashboard(view)
	for _, want := range []string{
		"Current posture",
		"Current activity",
		"Current threats",
		"Infrastructure",
		"Providers",
		"Uptime",
		"Last reload",
		"SQLite schema",
		"Worker count",
		`href="/v2/health"`,
		`href="/v2/providers"`,
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("v2 dashboard missing operator story fragment %q: %s", want, out)
		}
	}
}

func TestRenderV2TimelineEmptyStateOffersOperatorActions(t *testing.T) {
	out := renderV2TimelinePage(nil, "", "")
	for _, want := range []string{
		"No investigation started",
		"Quick actions",
		"Search IP",
		"Browse Timeline",
		"Recent Evidence",
		"Recent WAF Events",
		"Recent AbuseIPDB Reports",
		"/v2/investigate",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("v2 timeline empty state missing %q: %s", want, out)
		}
	}
}

func TestOperatorLiveScriptServed(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/static/operator-live.js", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected operator live script, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"data-live-panel-link", "data-live-panel-body", "toast"} {
		if !strings.Contains(body, want) {
			t.Fatalf("operator live script missing %q: %s", want, body)
		}
	}
	if !strings.Contains(body, "Open full page") {
		t.Fatalf("operator live script should include a full-page fallback action: %s", body)
	}
}

func TestProviderHealthCenter_RendersMissingSecretOnlyWhenEnabled(t *testing.T) {
	srv, _, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_ENABLED": "true",
		"AI_PROVIDER_OPENAI_MODEL":   "gpt-4.1-mini",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"OpenAI",
		"NOT CONFIGURED",
		"provider disabled by operator",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("providers page missing %q: %s", want, body)
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
	for _, want := range []string{"Anthropic", "credential store", "last test status"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected provider field %q in body: %s", want, body)
		}
	}
}

func TestProviderHealthCenter_UsesPersistedDisabledState(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"ABUSEIPDB_ENABLED": "true",
	})
	if err := saveProviderRuntimeSnapshot(context.Background(), sqlite.NewSetupStore(db), "abuseipdb", providerRuntimeSnapshot{Enabled: false}); err != nil {
		t.Fatalf("seed runtime snapshot: %v", err)
	}

	views := srv.providerHealthCenterView()
	for _, view := range views {
		if view.Name == "AbuseIPDB" {
			if view.EnabledState != "disabled" {
				t.Fatalf("expected persisted disabled state, got %#v", view)
			}
			return
		}
	}
	t.Fatal("expected AbuseIPDB health view")
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
		"update key",
		"test now",
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

func TestProvidersPageHealthyAIProviderSuppressesStaleFailureDiagnostics(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "openai-secret", true); err != nil {
		t.Fatalf("seed openai credential: %v", err)
	}
	now := time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC)
	if err := saveAIProviderStateToStore(context.Background(), sqlite.NewSetupStore(db), AIProviderState{
		OpenAI: AIProviderRecord{
			Enabled:           true,
			Model:             "gpt-4.1-mini",
			Healthy:           true,
			LastTestAt:        now,
			LastSuccessAt:     now,
			LastFailureAt:     now.Add(-time.Hour),
			LastTestStatus:    providerTestDisabledByOperator,
			LastTestLatencyMS: 42,
			LastErrorCode:     providerTestUnknownError,
		},
	}); err != nil {
		t.Fatalf("seed ai provider state: %v", err)
	}

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	openAICard := body[strings.Index(body, "<h2>OpenAI</h2>"):]
	for _, want := range []string{"OpenAI", "HEALTHY", "ready", "no error"} {
		if !strings.Contains(strings.ToLower(openAICard), strings.ToLower(want)) {
			t.Fatalf("providers page missing %q: %s", want, openAICard)
		}
	}
	for _, forbidden := range []string{"provider disabled by operator", "provider returned empty error"} {
		if strings.Contains(strings.ToLower(openAICard), strings.ToLower(forbidden)) {
			t.Fatalf("providers page should suppress stale failure diagnostic %q: %s", forbidden, openAICard)
		}
	}
}

func TestProvidersPageDisabledAIProviderSuppressesStaleHealthyDiagnostics(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "openai-secret", true); err != nil {
		t.Fatalf("seed openai credential: %v", err)
	}
	now := time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC)
	if err := saveAIProviderStateToStore(context.Background(), sqlite.NewSetupStore(db), AIProviderState{
		OpenAI: AIProviderRecord{
			Enabled:           false,
			Model:             "gpt-4.1-mini",
			Healthy:           true,
			LastTestAt:        now,
			LastSuccessAt:     now,
			LastTestStatus:    providerTestReady,
			LastTestLatencyMS: 42,
		},
	}); err != nil {
		t.Fatalf("seed ai provider state: %v", err)
	}

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	openAICard := body[strings.Index(body, "<h2>OpenAI</h2>"):]
	for _, want := range []string{"OpenAI", "DISABLED", "provider disabled by operator"} {
		if !strings.Contains(strings.ToLower(openAICard), strings.ToLower(want)) {
			t.Fatalf("providers page missing %q: %s", want, openAICard)
		}
	}
	for _, forbidden := range []string{"READY", "2026-06-14T10:00:00Z", "42ms"} {
		if strings.Contains(openAICard, forbidden) {
			t.Fatalf("providers page should suppress stale healthy diagnostic %q: %s", forbidden, openAICard)
		}
	}
}
