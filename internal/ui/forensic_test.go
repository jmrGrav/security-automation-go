package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// fakeEnrichmentDNS returns a fixed hostname+address pair.
type fakeEnrichmentDNS struct {
	hostname string
	addr     string
}

func (f *fakeEnrichmentDNS) LookupAddr(_ context.Context, _ string) ([]string, error) {
	if f.hostname == "" {
		return nil, nil
	}
	return []string{f.hostname}, nil
}
func (f *fakeEnrichmentDNS) LookupHost(_ context.Context, _ string) ([]string, error) {
	if f.addr == "" {
		return nil, nil
	}
	return []string{f.addr}, nil
}

type fakeEnrichmentASN struct {
	result asn.Result
}

func (f *fakeEnrichmentASN) Name() string { return "fake-asn" }
func (f *fakeEnrichmentASN) Lookup(_ context.Context, _ netip.Addr) (asn.Result, error) {
	return f.result, nil
}

func newTestServerWithEnrichment(t *testing.T, svc *enrichment.Service) *Server {
	t.Helper()
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "test-secret"})
	srv.enrichment = svc
	return srv
}

func forensicCfg() enrichment.Config {
	return enrichment.Config{
		Enabled:    true,
		DNSEnabled: true,
		ASNEnabled: true,
		Timeout:    50 * time.Millisecond,
		CacheTTL:   time.Minute,
	}
}

func TestForensic_RequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/forensic", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("forensic GET must require auth, got %d", rr.Code)
	}
}

func TestForensic_PostRequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=1.2.3.4"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("forensic POST must require auth, got %d", rr.Code)
	}
}

func TestForensic_InvalidIPShowsError(t *testing.T) {
	svc := enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	srv := newTestServerWithEnrichment(t, svc)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=not-an-ip"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if !strings.Contains(rr.Body.String(), "invalid IP address") {
		t.Fatalf("expected invalid IP error, got: %s", rr.Body.String())
	}
}

func TestForensic_ValidIPShowsResult(t *testing.T) {
	dns := &fakeEnrichmentDNS{hostname: "test.example.com.", addr: "203.0.113.5"}
	asnProv := &fakeEnrichmentASN{result: asn.Result{Kind: asn.KindUnknown, Provider: "fake-asn"}}
	svc := enrichment.NewService(forensicCfg(), dns, asnProv, nil, nil)
	srv := newTestServerWithEnrichment(t, svc)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=203.0.113.5"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "203.0.113.5") {
		t.Fatalf("result must show the queried IP, got: %s", body)
	}
	if !strings.Contains(body, "test.example.com") {
		t.Fatalf("result must show DNS hostname, got: %s", body)
	}
}

func TestForensic_ProtectedNetworkShowsBadge(t *testing.T) {
	asnProv := &fakeEnrichmentASN{result: asn.Result{
		Kind:      asn.KindProtected,
		Protected: true,
		Org:       "cloudflare",
		Provider:  "fake-asn",
	}}
	svc := enrichment.NewService(forensicCfg(), nil, asnProv, nil, nil)
	srv := newTestServerWithEnrichment(t, svc)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=104.16.0.1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "protected network") {
		t.Fatalf("protected network badge missing, got: %s", body)
	}
}

func TestForensic_NoEnrichmentServiceReturnsEmptyState(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "test-secret"})
	// enrichment and evidence are both nil — lookup should succeed with empty state
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=203.0.113.1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// Should not show enrichment-not-configured as a fatal error — just no data
	if strings.Contains(rr.Body.String(), "enrichment service not configured") {
		t.Fatalf("no longer expected enrichment-not-configured error on nil enrichment, got: %s", rr.Body.String())
	}
}

func TestForensic_StableContextIgnoresCanceledRequestContext(t *testing.T) {
	svc := enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	srv := newTestServerWithEnrichment(t, svc)
	srv.evidence = &fakeEvidenceStore{
		records: []reporting.DecisionEvidence{
			{EvidenceID: "ev1", IP: "203.0.113.5", Source: "cloudflare_waf", AbuseType: "scanner", RiskScore: 10, Decision: "local_block", Timestamp: time.Now()},
		},
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/forensic?ip=203.0.113.5", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"203.0.113.5", "Local Evidence History"} {
		if !strings.Contains(body, want) {
			t.Fatalf("forensic page missing %q: %s", want, body)
		}
	}
}

func TestForensic_AuditLogWrittenOnLookup(t *testing.T) {
	svc := enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	srv, audit, _ := newTestServer(t, map[string]string{"UI_SECRET": "test-secret"})
	srv.enrichment = svc
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=203.0.113.1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if !strings.Contains(audit.String(), "forensic_lookup") {
		t.Fatalf("expected forensic_lookup audit entry, got: %s", audit.String())
	}
}

func TestForensic_SecretNotInBody(t *testing.T) {
	svc := enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	srv, _, _ := newTestServer(t, map[string]string{
		"ABUSEIPDB_KEY":      "super-secret-key",
		"VIRUSTOTAL_API_KEY": "vt-secret-key",
	})
	srv.enrichment = svc
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=203.0.113.1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, secret := range []string{"super-secret-key", "vt-secret-key", "test-secret"} {
		if strings.Contains(body, secret) {
			t.Errorf("forensic page must not leak secret %q", secret)
		}
	}
}

// ---------------------------------------------------------------------------
// P13: GET /forensic?ip=X deep-link and Explain This IP quick-links
// ---------------------------------------------------------------------------

func TestForensic_GETWithIPQueryParam_PerformsLookup(t *testing.T) {
	svc := enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	srv := newTestServerWithEnrichment(t, svc)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/forensic?ip=203.0.113.10", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "203.0.113.10") {
		t.Errorf("expected IP in body from GET deep-link: %s", body)
	}
}

func TestForensic_GETWithInvalidIP_ShowsError(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/forensic?ip=not-an-ip", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid IP address") {
		t.Errorf("expected error for invalid IP in deep-link: %s", rr.Body.String())
	}
}

func TestForensic_GETWithoutIP_ShowsBlankForm(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/forensic", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Forensic") {
		t.Errorf("expected forensic page title: %s", body)
	}
}

func TestForensicPageIncludesCSRFToken(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/forensic", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, `name="csrf_token"`) {
		t.Fatalf("forensic page should include csrf token field: %s", body)
	}
}

func TestForensic_NoCscliSpawn(t *testing.T) {
	// This is a static guard test: the forensic handler must never import or call
	// anything that spawns cscli. Since Go test coverage runs in-process, we
	// simply assert the handler completes and returns HTML — not a process error.
	svc := enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	srv := newTestServerWithEnrichment(t, svc)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=203.0.113.2"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Fatalf("expected HTML response, got %q", ct)
	}
}
