package ui

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/security/audit"
)

func TestAIExplainEndpointRequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	req := httptest.NewRequest(http.MethodPost, "/ui/ai/explain", strings.NewReader(`{"subject_type":"provider","subject_id":"cloudflare","provider_preference":"auto"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected auth redirect, got %d", rr.Code)
	}
}

func TestAIExplainEndpointRequiresCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodPost, "/ui/ai/explain", strings.NewReader(`{"subject_type":"provider","subject_id":"cloudflare","provider_preference":"auto"}`))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected csrf rejection, got %d", rr.Code)
	}
}

func TestAIExplainEndpointRejectsInvalidJSONAndSubject(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	cookie := loginCookie(t, srv, "test-password-123!@#")
	invalidJSON := httptest.NewRequest(http.MethodPost, "/ui/ai/explain", strings.NewReader(`{`))
	invalidJSON.AddCookie(cookie)
	invalidJSON.Header.Set("Content-Type", "application/json")
	invalidJSON.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, invalidJSON)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid json rejection, got %d", rr.Code)
	}

	badSubject := httptest.NewRequest(http.MethodPost, "/ui/ai/explain", strings.NewReader(`{"subject_type":"oops","subject_id":"1","provider_preference":"auto"}`))
	badSubject.AddCookie(cookie)
	badSubject.Header.Set("Content-Type", "application/json")
	badSubject.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, badSubject)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected invalid subject rejection, got %d", rr.Code)
	}
}

func TestAIExplainEndpointReturnsUnavailableJSON(t *testing.T) {
	srv, audit, _ := newTestServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodPost, "/ui/ai/explain", strings.NewReader(`{"subject_type":"provider","subject_id":"cloudflare","provider_preference":"auto"}`))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`"provider":"none"`, `"quota_state":"UNKNOWN"`, `"explanation":"AI explain unavailable`} {
		if !strings.Contains(body, want) {
			t.Fatalf("response missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "ui-secret-value") {
		t.Fatalf("AI explain endpoint leaked secret: %s", body)
	}
	if !strings.Contains(audit.String(), "ai_explain_unavailable") {
		t.Fatalf("expected audit entry for unavailable response, got %s", audit.String())
	}
}

func TestAIExplainAuditEntriesIncludeUsefulMetadata(t *testing.T) {
	srv, auditSink, _ := newTestServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodPost, "/ui/ai/explain", strings.NewReader(`{"subject_type":"provider","subject_id":"cloudflare","provider_preference":"auto"}`))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 response, got %d: %s", rr.Code, rr.Body.String())
	}

	var requested *audit.AuditEntry
	var unavailable *audit.AuditEntry
	for i := range auditSink.Entries() {
		entry := auditSink.Entries()[i]
		switch entry.Action {
		case "ai_explain_requested":
			requested = &entry
		case "ai_explain_unavailable":
			unavailable = &entry
		}
	}

	if requested == nil {
		t.Fatal("expected ai_explain_requested audit entry")
	}
	if requested.Target != "cloudflare" {
		t.Fatalf("expected requested target to preserve subject id, got %+v", *requested)
	}
	if requested.Result != "requested" {
		t.Fatalf("expected requested result, got %+v", *requested)
	}
	if requested.EventID == "" || requested.Correlation != requested.EventID {
		t.Fatalf("expected requested event_id/correlation parity, got %+v", *requested)
	}

	if unavailable == nil {
		t.Fatal("expected ai_explain_unavailable audit entry")
	}
	if unavailable.Target != "cloudflare" {
		t.Fatalf("expected unavailable target to preserve subject id, got %+v", *unavailable)
	}
	if unavailable.Result != "unavailable" {
		t.Fatalf("expected unavailable result, got %+v", *unavailable)
	}
	if unavailable.EventID == "" || unavailable.Correlation != unavailable.EventID {
		t.Fatalf("expected unavailable event_id/correlation parity, got %+v", *unavailable)
	}
}

func TestAIExplainWidgetsRenderOnReadOnlyPages(t *testing.T) {
	var buf bytes.Buffer
	if err := TimelinePage(TimelineView{
		Entries: []audit.TimelineEvent{{Timestamp: "2026-06-01T09:00:00Z", Scope: "ui", EventType: "security_intelligence_lookup", Severity: "healthy", ActorSource: "ui", Action: "security_intelligence_lookup", Target: "203.0.113.10", Result: "neutral"}},
	}, "csrf-token").Render(context.Background(), &buf); err != nil {
		t.Fatalf("render timeline: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"Explain with AI", `data-ai-explain-result`, `subject_type" value="timeline_event"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("timeline page missing %q", want)
		}
	}

	buf.Reset()
	if err := AuditTrailPage(AuditTrailView{Entries: []audit.AuditEntry{{Timestamp: "2026-06-01T09:01:00Z", Action: "provider_test_lookup", Target: "Cloudflare", Result: "dry-run", EventID: "evt-1"}}}, "csrf-token").Render(context.Background(), &buf); err != nil {
		t.Fatalf("render audit trail: %v", err)
	}
	body = buf.String()
	for _, want := range []string{"Explain with AI", `data-ai-explain-result`, `subject_type" value="audit_event"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit page missing %q", want)
		}
	}

	buf.Reset()
	if err := ProviderHealthCenterPage([]providerHealthCenterEntry{{
		Name:            "Cloudflare",
		Description:     "read-only boundary",
		Status:          "NORMAL",
		Mode:            "dry-run",
		EnabledState:    "enabled",
		ConfiguredState: "configured",
		QuotaPlan:       "Plan: Free",
		QuotaSource:     "headers",
		QuotaAge:        "fresh",
		LastValidation:  "fresh",
		LastSuccess:     "2026-06-01T09:00:00Z",
		LastError:       "none",
		ErrorCount:      "0",
		RateLimitCount:  "0",
		QuotaRemaining:  "92%",
		QuotaUsed:       "8%",
		QuotaReset:      "2026-06-01T10:00:00Z",
		AvgLatency:      "12ms",
		LastLatency:     "9ms",
		CacheHits:       "4",
		CacheMisses:     "1",
		LastLookup:      "2026-06-01T09:00:00Z",
		StatusCode:      "200",
	}}, "csrf-token").Render(context.Background(), &buf); err != nil {
		t.Fatalf("render provider health: %v", err)
	}
	body = buf.String()
	for _, want := range []string{"Explain with AI", `data-ai-explain-result`, `subject_type" value="provider"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("provider page missing %q", want)
		}
	}

	buf.Reset()
	if err := SecurityIntelligencePage(SecurityIntelligenceView{
		CurrentIP:         "203.0.113.10",
		HasData:           true,
		Outcome:           "neutral",
		Kind:              "unknown",
		DNS:               "example.test",
		DNSForwardConfirm: "yes",
		ASN:               "AS64500",
		Organisation:      "Example Org",
		Protected:         "false",
		NoHardBan:         "true",
		ScoreDelta:        "0",
		HardBanReason:     "provider failures stay neutral",
		ProviderNote:      "Provider failures stay neutral. External signal alone cannot hard-ban.",
		CloudflareStatus:  "unknown",
		CrowdSecStatus:    "unknown",
		EvidencePreview:   []string{"IP: 203.0.113.10", "ASN: AS64500"},
	}, "csrf-token").Render(context.Background(), &buf); err != nil {
		t.Fatalf("render intelligence: %v", err)
	}
	body = buf.String()
	for _, want := range []string{"Explain with AI", `data-ai-explain-result`, `subject_type" value="intelligence"`} {
		if !strings.Contains(body, want) {
			t.Fatalf("intelligence page missing %q", want)
		}
	}
}

func TestAIExplainScriptIsSelfHosted(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/static/ai-explain.js", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"fetch(", "/ui/ai/explain", "AI explain unavailable"} {
		if !strings.Contains(body, want) {
			t.Fatalf("script missing %q", want)
		}
	}
	if strings.Contains(body, "https://") || strings.Contains(body, "http://") {
		t.Fatalf("script must remain self-hosted only: %s", body)
	}
}
