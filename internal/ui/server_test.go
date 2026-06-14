package ui

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	aigateway "github.com/jm/security-automation-go/internal/ai/gateway"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aianthropic "github.com/jm/security-automation-go/internal/ai/providers/anthropic"
	aigemini "github.com/jm/security-automation-go/internal/ai/providers/gemini"
	aiopenai "github.com/jm/security-automation-go/internal/ai/providers/openai"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/ui/auth"
)

func TestServer_RequiresSessionCookie(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect to login, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected login redirect, got %q", loc)
	}
}

// TestServer_SessionCookieAttributes verifies the full security attribute set on
// every login path: HttpOnly, SameSite=Strict, and Secure=true.
// Secure is always true regardless of transport because the UI is bound to
// 127.0.0.1 only, and both http://localhost and http://127.0.0.1 are treated
// as "potentially trustworthy" by modern browsers (W3C Secure Contexts §3.2,
// Chrome, Firefox 84+), so the Secure attribute is honoured on loopback
// without HTTPS.
func TestServer_SessionCookieAttributes(t *testing.T) {
	cases := []struct {
		name string
		tls  bool
		xfwd string
	}{
		{"plain_http_localhost", false, ""},
		{"https_direct", true, ""},
		{"reverse_proxy_https", false, "https"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _, _ := newTestServer(t, nil)
			form := strings.NewReader("password=test-password-123!@#")
			req := httptest.NewRequest(http.MethodPost, "/login", form)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if tc.tls {
				req.TLS = &tls.ConnectionState{}
			}
			if tc.xfwd != "" {
				req.Header.Set("X-Forwarded-Proto", tc.xfwd)
			}
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)

			if rr.Code != http.StatusFound {
				t.Fatalf("expected login redirect, got %d", rr.Code)
			}
			cookies := rr.Result().Cookies()
			if len(cookies) == 0 {
				t.Fatal("expected session cookie")
			}
			c := cookies[0]
			if !c.HttpOnly {
				t.Fatal("session cookie must be HttpOnly")
			}
			if c.SameSite != http.SameSiteStrictMode {
				t.Fatalf("expected SameSite=Strict, got %v", c.SameSite)
			}
			if !c.Secure {
				t.Fatal("session cookie must always be Secure (localhost exception applies)")
			}
		})
	}
}

// TestServer_LogoutClearsCookieSecurely ensures the logout clear-cookie also
// carries Secure=true so the browser honours the Max-Age:-1 expiry on the
// same Secure cookie that was originally set.
func TestServer_LogoutClearsCookieSecurely(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	// Log in first to obtain a valid session cookie.
	form := strings.NewReader("password=test-password-123!@#")
	loginReq := httptest.NewRequest(http.MethodPost, "/login", form)
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	loginRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRR, loginReq)
	if loginRR.Code != http.StatusFound {
		t.Fatalf("login failed: %d", loginRR.Code)
	}
	sessionCookie := loginRR.Result().Cookies()[0]

	// Submit CSRF-less logout — just check the Set-Cookie header directly.
	csrfToken := srv.csrfTokenFor(sessionCookie.Value)
	logoutReq := httptest.NewRequest(http.MethodPost, "/logout", nil)
	logoutReq.Header.Set("X-CSRF-Token", csrfToken)
	logoutReq.AddCookie(sessionCookie)
	logoutRR := httptest.NewRecorder()
	srv.Handler().ServeHTTP(logoutRR, logoutReq)

	var clearCookie *http.Cookie
	for _, c := range logoutRR.Result().Cookies() {
		if c.Name == sessionCookieName {
			clearCookie = c
			break
		}
	}
	if clearCookie == nil {
		t.Fatal("expected logout to emit a clear-cookie")
	}
	if !clearCookie.Secure {
		t.Fatal("logout clear-cookie must be Secure so the browser expires the matching Secure session cookie")
	}
	if clearCookie.MaxAge != -1 {
		t.Fatalf("expected MaxAge=-1, got %d", clearCookie.MaxAge)
	}
}

func TestServer_LoginWritesAuditLog(t *testing.T) {
	srv, audit, secretPath := newTestServer(t, nil)
	_ = secretPath

	form := strings.NewReader("password=test-password-123!@#")
	req := httptest.NewRequest(http.MethodPost, "/login", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if got := audit.String(); !strings.Contains(got, "login_success") {
		t.Fatalf("expected audit log entry, got %q", got)
	}
}

func TestServer_MutationsDisabledByDefault(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/actions/cloudflare/ban", strings.NewReader("ip=203.0.113.4"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected mutations to be rejected by default, got %d", rr.Code)
	}
}

func TestServer_CSRFRequiredWhenMutationsEnabled(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_MUTATIONS_ENABLED":         "1",
		"CLOUDFLARE_MUTATIONS_ENABLED": "1",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/actions/cloudflare/ban", strings.NewReader("ip=203.0.113.4"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected CSRF rejection, got %d", rr.Code)
	}
}

func TestServer_ProviderKeysAreMasked(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"SPAMHAUS_API_KEY":   "spamhaus-secret",
		"VIRUSTOTAL_API_KEY": "virustotal-secret",
		"SPAMHAUS_ENABLED":   "1",
		"VIRUSTOTAL_ENABLED": "1",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, secret := range []string{"spamhaus-secret", "virustotal-secret"} {
		if strings.Contains(body, secret) {
			t.Fatalf("provider page leaked secret %q: %s", secret, body)
		}
	}
}

func TestServer_DashboardShowsFallbackAndCloudflareStates(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"CrowdSec unavailable / read-only fallback",
		"Cloudflare configured dry-run",
		"UI ready on 127.0.0.1:9091",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q: %s", want, body)
		}
	}
	// OpenResty detail is now driven by the system detector (binary+service),
	// so the exact text is environment-dependent. Verify that some OpenResty
	// panel exists rather than a specific message.
	if !strings.Contains(body, "OpenResty") {
		t.Fatal("dashboard missing OpenResty panel")
	}
}

func TestServer_SidebarIncludesFuturePages(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"Security Intelligence",
		"Timeline",
		"Audit Trail",
		"Trusted Networks",
		"Cloudflare Diff",
		"About/System",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard sidebar missing %q: %s", want, body)
		}
	}
}

func TestServer_ImplementedWorkflowRoutesAreNotMarkedSoon(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, label := range []string{
		"Timeline</a><span class=\"soon\">soon</span>",
		"Cloudflare Diff</a><span class=\"soon\">soon</span>",
	} {
		if strings.Contains(body, label) {
			t.Fatalf("implemented workflow route still marked soon: %q", label)
		}
	}
	for _, hidden := range []string{`href="/replay"`, `href="/deban"`} {
		if strings.Contains(body, hidden) {
			t.Fatalf("soon route link %q should be hidden from the default sidebar: %s", hidden, body)
		}
	}
}

func TestServer_ActiveNavMarksCurrentPage(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, `aria-current="page">Providers</a>`) {
		t.Fatalf("providers page should mark active nav item: %s", body)
	}
	if strings.Contains(body, `aria-current="page">Dashboard</a>`) {
		t.Fatalf("providers page must not mark dashboard active: %s", body)
	}
}

func TestServer_ConsolePagesAreSelfContained(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	for _, path := range []string{"/", "/providers", "/about", "/audit", "/timeline"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)

		if got := rr.Header().Get("Content-Security-Policy"); !strings.Contains(got, "script-src 'self'") {
			t.Fatalf("%s missing self-only CSP, got %q", path, got)
		}
		body := rr.Body.String()
		for _, forbidden := range []string{"unpkg.com", "http://", "https://"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s should not reference %q: %s", path, forbidden, body)
			}
		}
	}
}

func TestServer_AboutPageHidesSecrets(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"SPAMHAUS_API_KEY": "spamhaus-secret",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/about", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "spamhaus-secret") || strings.Contains(body, "ui-secret-value") {
		t.Fatalf("about page leaked a secret: %s", body)
	}
}

func TestServer_AuditTrailEmptyState(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := &http.Cookie{Name: sessionCookieName, Value: "seeded-session"}
	srv.mu.Lock()
	srv.sessions[cookie.Value] = time.Now().UTC().Add(time.Hour)
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/audit", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "No audit events yet") {
		t.Fatalf("audit page should render empty state, got %s", body)
	}
}

func TestServer_ReservedRoutesRequireAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	for _, path := range []string{"/deban"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("%s should require auth, got %d", path, rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/login" {
			t.Fatalf("%s should redirect to login, got %q", path, loc)
		}
	}
}

func TestServer_WorkflowRoutesRequireAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	for _, path := range []string{"/timeline", "/cloudflare/diff", "/replay", "/recovery", "/drift"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("%s should require auth, got %d", path, rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/login" {
			t.Fatalf("%s should redirect to login, got %q", path, loc)
		}
	}
}

func TestServer_PagesAreSelfContained(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	for _, path := range []string{"/", "/forensic", "/intelligence", "/trusted-networks", "/timeline", "/cloudflare/diff", "/replay", "/recovery", "/drift"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)

		body := rr.Body.String()
		for _, forbidden := range []string{"unpkg.com", "hx-boost"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("%s should not reference %q: %s", path, forbidden, body)
			}
		}
		if path == "/forensic" && !strings.Contains(body, "Forensic IP Lookup") {
			t.Fatalf("forensic page missing lookup shell: %s", body)
		}
	}
}

func TestServer_SecurityHeadersPresentOnAuthenticatedRoutes(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "test-secret"})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	for _, path := range []string{"/", "/providers"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)

		for _, header := range []string{
			"X-Content-Type-Options",
			"X-Frame-Options",
			"Referrer-Policy",
			"Content-Security-Policy",
			"Cache-Control",
		} {
			if rr.Header().Get(header) == "" {
				t.Errorf("path %s: missing security header %q", path, header)
			}
		}
	}
}

func TestServer_SessionExpiredAfterTTL(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "test-secret"})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// Manually expire the session.
	srv.mu.Lock()
	for k := range srv.sessions {
		srv.sessions[k] = time.Now().UTC().Add(-time.Hour)
	}
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect to login after session expiry, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected /login redirect, got %q", loc)
	}
}

func TestServer_ExpiredSessionEvictedFromStore(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "test-secret"})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	srv.mu.Lock()
	initialCount := len(srv.sessions)
	for k := range srv.sessions {
		srv.sessions[k] = time.Now().UTC().Add(-time.Hour)
	}
	srv.mu.Unlock()

	if initialCount == 0 {
		t.Fatal("expected at least one session after login")
	}

	// Send the expired cookie — isAuthed must evict it from the store.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	srv.mu.Lock()
	remaining := len(srv.sessions)
	srv.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("expected expired session to be evicted, got %d remaining", remaining)
	}
}

func TestServer_PrunesExpiredSessionsWithoutCookieReplay(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "test-secret"})

	srv.mu.Lock()
	srv.sessions["stale-1"] = time.Now().UTC().Add(-2 * time.Hour)
	srv.sessions["stale-2"] = time.Now().UTC().Add(-time.Hour)
	srv.sessions["live"] = time.Now().UTC().Add(time.Hour)
	srv.mu.Unlock()

	srv.pruneSessions()

	srv.mu.Lock()
	defer srv.mu.Unlock()
	if _, ok := srv.sessions["stale-1"]; ok {
		t.Fatal("expected stale-1 to be pruned")
	}
	if _, ok := srv.sessions["stale-2"]; ok {
		t.Fatal("expected stale-2 to be pruned")
	}
	if _, ok := srv.sessions["live"]; !ok {
		t.Fatal("expected live session to remain")
	}
}

func TestServer_RateLimiterEvictsStaleEntries(t *testing.T) {
	lim := newRateLimiter(5, 10*time.Millisecond)

	// Fill the limiter.
	for i := 0; i < 3; i++ {
		lim.Allow("client-a")
	}

	// Wait for the window to pass, then call Allow on a different key.
	// The stale bucket for "client-a" should be evicted.
	time.Sleep(30 * time.Millisecond)
	lim.Allow("client-b")

	lim.mu.Lock()
	_, stillPresent := lim.clients["client-a"]
	lim.mu.Unlock()

	if stillPresent {
		t.Fatal("stale rate-limiter bucket should have been evicted")
	}
}

func newTestServer(t *testing.T, env map[string]string) (*Server, *BufferAuditSink, string) {
	t.Helper()
	dataDir := t.TempDir()
	for k, v := range env {
		t.Setenv(k, v)
	}
	t.Setenv("CF_API_TOKEN", "test-token")
	t.Setenv("CF_ZONE_ID", "test-zone")
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
	secretsPath := cfg.UI.SecretFile
	aiCfg := ai.FromEnv()
	audit := NewBufferAuditSink()
	builder := func(aiCfg ai.Config) aigateway.Gateway {
		providers := make([]providers.Provider, 0, 3)
		if p := aiopenai.New(aiCfg.OpenAI); p.Enabled() {
			providers = append(providers, p)
		}
		if p := aianthropic.New(aiCfg.Anthropic); p.Enabled() {
			providers = append(providers, p)
		}
		if p := aigemini.New(aiCfg.Gemini); p.Enabled() {
			providers = append(providers, p)
		}
		return aigateway.NewService(aiCfg, providers, nil, audit)
	}

	db, err := sqlite.New(cfg.StateDir)
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	srv, err := NewServer(cfg, Options{
		SecretProvider:   NewFileSecretProvider(secretsPath),
		AuditSink:        audit,
		AIExplainBuilder: builder,
		AIConfig:         aiCfg,
		SetupStore:       sqlite.NewSetupStore(db),
		ProviderFactories: map[string]ProviderFactory{
			"openai":    func(pc ai.ProviderConfig) providers.Provider { return aiopenai.New(pc) },
			"anthropic": func(pc ai.ProviderConfig) providers.Provider { return aianthropic.New(pc) },
			"gemini":    func(pc ai.ProviderConfig) providers.Provider { return aigemini.New(pc) },
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Seed default admin password for tests
	hash, _ := auth.HashPassword("test-password-123!@#")
	_ = srv.setupStore.SetSetting(context.Background(), "admin_password_hash", hash)
	_ = srv.setupStore.MarkComplete(context.Background())

	return srv, audit, secretsPath
}

func loginCookie(t *testing.T, srv *Server, password string) *http.Cookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader("password="+password))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("login failed with status %d body=%s", rr.Code, rr.Body.String())
	}
	cookies := rr.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("missing session cookie")
	}
	return cookies[0]
}

func TestLogout_RequiresCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing CSRF on logout, got %d", rr.Code)
	}
}

func TestLogout_ValidCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect after valid CSRF logout, got %d", rr.Code)
	}
}

func TestLogoutGET_ClearsSessionAndRedirects(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect after GET logout, got %d", rr.Code)
	}
	// Session must be invalidated — authenticated page must now return redirect
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.AddCookie(cookie)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusFound {
		t.Fatalf("expected redirect to login after session destroyed, got %d", rr2.Code)
	}
}

func TestLogoutGET_RequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/logout", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect to login for unauthenticated logout, got %d", rr.Code)
	}
}

func TestSidebarContainsLogoutLink(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), `href="/logout"`) {
		t.Fatalf("sidebar must contain a logout link, got: %s", rr.Body.String()[:min(500, rr.Body.Len())])
	}
}

func TestForensicLookup_RequiresCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	form := strings.NewReader("ip=1.2.3.4")
	req := httptest.NewRequest(http.MethodPost, "/forensic", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing CSRF on forensic lookup, got %d", rr.Code)
	}
}

func TestIntelligenceLookup_RequiresCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	form := strings.NewReader("ip=1.2.3.4")
	req := httptest.NewRequest(http.MethodPost, "/intelligence", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing CSRF on intelligence lookup, got %d", rr.Code)
	}
}

func TestIntelligenceLookup_Success(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	form := strings.NewReader("ip=1.2.3.4")
	req := httptest.NewRequest(http.MethodPost, "/intelligence", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
}
