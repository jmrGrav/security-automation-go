package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestTrustedNetworks_RequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/trusted-networks", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect to login, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected /login redirect, got %q", loc)
	}
}

func TestTrustedNetworks_RenderRegistryEntries(t *testing.T) {
	srv, audit, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/trusted-networks", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"Cloudflare",
		"Google",
		"Microsoft/Bing",
		"BetterStack",
		"UptimeRobot/Pingdom",
		"OpenAI GPTBot",
		"OpenAI SearchBot",
		"GitHub Copilot",
		"Anthropic",
		"OpenAI ChatGPT-User",
		"NoHardBan=true",
		"HardBanAllowed=false",
		"allowlisted=false",
		"Cloudflare whitelist not synced",
		"CrowdSec allowlist not synced",
		"SourceURL",
		"manual review required / too volatile",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("trusted networks page missing %q: %s", want, body)
		}
	}
	if !strings.Contains(body, "https://openai.com/gptbot.json") {
		t.Fatalf("expected source URL to be rendered, got: %s", body)
	}
	if !strings.Contains(body, "https://api.github.com/meta") {
		t.Fatalf("expected GitHub source URL to be rendered, got: %s", body)
	}
	if strings.Contains(body, "auto-allowlist") {
		t.Fatalf("page must not render auto-allowlist action: %s", body)
	}
	if strings.Contains(body, "ui-secret-value") {
		t.Fatalf("page leaked secret: %s", body)
	}
	if !strings.Contains(audit.String(), "trusted_networks_view") {
		t.Fatalf("expected trusted_networks_view audit event, got: %s", audit.String())
	}
}

func TestTrustedNetworks_ExportIsReadOnlyAndDeterministic(t *testing.T) {
	srv, audit, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	export := func() string {
		req := httptest.NewRequest(http.MethodGet, "/trusted-networks/export", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected export status 200, got %d", rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Fatalf("expected text/plain export, got %q", ct)
		}
		return rr.Body.String()
	}

	first := export()
	second := export()

	for _, want := range []string{
		"Trusted Networks Registry Export",
		"[OpenAI GPTBot]",
		"organization=openai-gptbot",
		"cloudflare_whitelist=not synced",
		"allowlisted=false",
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("export missing %q: %s", want, first)
		}
	}
	if first != second {
		t.Fatalf("export must be deterministic and read-only; first=%q second=%q", first, second)
	}
	if !strings.Contains(audit.String(), "trusted_networks_export") {
		t.Fatalf("expected trusted_networks_export audit event, got: %s", audit.String())
	}
}
