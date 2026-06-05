package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/security/enrichment"
	"github.com/jm/security-automation-go/internal/security/enrichment/asn"
)

type fakeLookupProvider struct {
	name    string
	mode    enrichment.LookupMode
	verdict enrichment.ProviderVerdict
}

func (f fakeLookupProvider) Name() string                { return f.name }
func (f fakeLookupProvider) Mode() enrichment.LookupMode { return f.mode }
func (f fakeLookupProvider) Lookup(_ context.Context, _ netip.Addr) (enrichment.ProviderVerdict, error) {
	return f.verdict, nil
}

func TestSecurityIntelligence_RequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "ui-secret-value",
	})

	for _, req := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/intelligence", nil),
		httptest.NewRequest(http.MethodPost, "/intelligence", strings.NewReader("ip=203.0.113.1")),
	} {
		if req.Method == http.MethodPost {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Fatalf("%s should require auth, got %d", req.Method, rr.Code)
		}
		if loc := rr.Header().Get("Location"); loc != "/login" {
			t.Fatalf("expected login redirect, got %q", loc)
		}
	}
}

func TestSecurityIntelligence_InvalidIPRejected(t *testing.T) {
	srv, audit, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "ui-secret-value",
	})
	srv.enrichment = enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodPost, "/intelligence", strings.NewReader("ip=not-an-ip"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "invalid IP address") {
		t.Fatalf("expected invalid IP error, got: %s", body)
	}
	if !strings.Contains(audit.String(), "security_intelligence_lookup") {
		t.Fatalf("expected audit log entry, got: %s", audit.String())
	}
}

func TestSecurityIntelligence_CleanIPNeutral(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "ui-secret-value",
	})
	srv.enrichment = enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodPost, "/intelligence", strings.NewReader("ip=203.0.113.4"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(strings.ToUpper(body), "NEUTRAL") {
		t.Fatalf("expected neutral result, got: %s", body)
	}
	if strings.Contains(body, "super-secret") {
		t.Fatalf("clean IP page leaked secret: %s", body)
	}
}

func TestSecurityIntelligence_ProtectedIPNoHardBan(t *testing.T) {
	dns := &fakeEnrichmentDNS{hostname: "protected.example.com.", addr: "104.16.0.1"}
	asnProv := &fakeEnrichmentASN{result: asn.Result{
		Kind:      asn.KindProtected,
		Protected: true,
		Org:       "cloudflare",
		Provider:  "static",
	}}
	svc := enrichment.NewService(forensicCfg(), dns, asnProv, nil, nil)
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "ui-secret-value",
	})
	srv.enrichment = svc
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodPost, "/intelligence", strings.NewReader("ip=104.16.0.1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "nohardban") {
		t.Fatalf("expected NoHardBan rendering, got: %s", body)
	}
	if !strings.Contains(strings.ToLower(body), "protected") {
		t.Fatalf("expected protected rendering, got: %s", body)
	}
}

func TestSecurityIntelligence_ExternalSignalAloneCannotHardBan(t *testing.T) {
	fakeProvider := fakeLookupProvider{
		name: "abuseipdb",
		mode: enrichment.LookupModeAutomatic,
		verdict: enrichment.ProviderVerdict{
			Provider: "AbuseIPDB",
			Mode:     enrichment.LookupModeAutomatic,
			Score:    80,
			Note:     "external signal only",
		},
	}
	svc := enrichment.NewService(forensicCfg(), nil, nil, []enrichment.LookupProvider{fakeProvider}, nil)
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET":          "ui-secret-value",
		"ABUSEIPDB_ENABLED":  "1",
		"SPAMHAUS_ENABLED":   "1",
		"VIRUSTOTAL_ENABLED": "1",
	})
	srv.enrichment = svc
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodPost, "/intelligence", strings.NewReader("ip=203.0.113.7"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(strings.ToLower(body), "external signal alone cannot hard-ban") {
		t.Fatalf("expected hard-ban guard text, got: %s", body)
	}
	if strings.Contains(strings.ToUpper(body), "HARD-BAN ALLOWED") {
		t.Fatalf("external signal alone must not hard-ban: %s", body)
	}
}

func TestSecurityIntelligence_ProviderDisabledStateVisible(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET":          "ui-secret-value",
		"ABUSEIPDB_ENABLED":  "0",
		"SPAMHAUS_ENABLED":   "1",
		"VIRUSTOTAL_ENABLED": "1",
	})
	srv.enrichment = enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodPost, "/intelligence", strings.NewReader("ip=203.0.113.8"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if !strings.Contains(strings.ToLower(rr.Body.String()), "disabled") {
		t.Fatalf("expected disabled provider state, got: %s", rr.Body.String())
	}
}

func TestSecurityIntelligence_AuditLogWritten(t *testing.T) {
	srv, audit, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "ui-secret-value",
	})
	srv.enrichment = enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodPost, "/intelligence", strings.NewReader("ip=203.0.113.9"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(audit.String(), "security_intelligence_lookup") {
		t.Fatalf("expected security_intelligence_lookup audit event, got: %s", audit.String())
	}
}

func TestSecurityIntelligence_NoSecretRendered(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET":          "ui-secret-value",
		"ABUSEIPDB_KEY":      "super-secret",
		"VIRUSTOTAL_API_KEY": "vt-secret",
		"SPAMHAUS_API_KEY":   "spamhaus-secret",
	})
	srv.enrichment = enrichment.NewService(forensicCfg(), nil, nil, nil, nil)
	cookie := loginCookie(t, srv, "ui-secret-value")

	req := httptest.NewRequest(http.MethodPost, "/intelligence", strings.NewReader("ip=203.0.113.10"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, secret := range []string{"super-secret", "vt-secret", "spamhaus-secret", "ui-secret-value"} {
		if strings.Contains(body, secret) {
			t.Fatalf("intelligence page leaked secret %q: %s", secret, body)
		}
	}
}
