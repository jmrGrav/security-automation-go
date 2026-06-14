package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

func TestEvidenceDetailPage_RendersEvidenceAndSuppressionReason(t *testing.T) {
	store := &fakeEvidenceStore{
		records: []reporting.DecisionEvidence{
			{
				EvidenceID:        "ev1",
				Timestamp:         time.Date(2026, 6, 13, 14, 30, 0, 0, time.UTC),
				Source:            "cloudflare_waf",
				IP:                "1.2.3.4",
				Hostname:          "example.test",
				URI:               "/login",
				AbuseType:         "scanner",
				RiskScore:         42,
				Confidence:        0.87,
				Decision:          "suppress",
				Suppressed:        true,
				SuppressionReason: "low_confidence",
				NormalizedEvent: classifier.Event{
					Source: "cloudflare_waf",
					IP:     "1.2.3.4",
				},
				Metadata: map[string]any{"source_path": "/tmp/events.jsonl"},
			},
		},
	}
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/evidence/ev1", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		"data-live-panel-content",
		"Evidence Detail",
		"ev1",
		"cloudflare_waf",
		"1.2.3.4",
		"low_confidence",
		"Normalized event",
		"Raw evidence JSON",
		`data-copy-target="#normalized-json"`,
		`data-copy-target="#raw-evidence-json"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in detail page, body: %s", want, body)
		}
	}
}

func TestEvidenceDetailPage_Returns404ForUnknownEvidence(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = &fakeEvidenceStore{records: nil}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/evidence/missing", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

func TestEvidenceDetailPage_PanelFallbackForUnknownEvidence(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = &fakeEvidenceStore{records: nil}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/evidence/missing", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-Live-Panel", "1")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 fallback panel, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"data-live-panel-content", "Evidence not found", "Open full page"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected %q in fallback panel body: %s", want, body)
		}
	}
}

func TestEvidenceDetailPage_StableContextIgnoresCanceledRequestContext(t *testing.T) {
	store := &fakeEvidenceStore{
		records: []reporting.DecisionEvidence{
			{
				EvidenceID: "ev1",
				Timestamp:  time.Date(2026, 6, 13, 14, 30, 0, 0, time.UTC),
				Source:     "cloudflare_waf",
				IP:         "1.2.3.4",
				Hostname:   "example.test",
				URI:        "/login",
				AbuseType:  "scanner",
				RiskScore:  42,
				Confidence: 0.87,
				Decision:   "suppress",
				Suppressed: true,
				NormalizedEvent: classifier.Event{
					Source: "cloudflare_waf",
					IP:     "1.2.3.4",
				},
			},
		},
	}
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/evidence/ev1", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"data-live-panel-content", "ev1", "1.2.3.4"} {
		if !strings.Contains(body, want) {
			t.Fatalf("detail page missing %q: %s", want, body)
		}
	}
}
