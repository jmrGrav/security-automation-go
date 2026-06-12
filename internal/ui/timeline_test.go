package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/services/reporting"
)

func TestTimelineEmptyState(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := &http.Cookie{Name: sessionCookieName, Value: "seeded-session"}
	srv.mu.Lock()
	srv.sessions[cookie.Value] = time.Now().UTC().Add(time.Hour)
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "Security Timeline") {
		t.Fatalf("timeline page missing heading: %s", body)
	}
	if !strings.Contains(body, "No timeline events yet") {
		t.Fatalf("timeline empty state missing: %s", body)
	}
	if strings.Contains(body, "<table>") {
		t.Fatalf("empty timeline page must not render a table: %s", body)
	}
}

func TestTimelineIncludesEvidenceEvents(t *testing.T) {
	now := time.Now().UTC()
	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{
				EvidenceID:        "ev-cf-1",
				Source:            "cloudflare_waf",
				IP:                "1.2.3.4",
				AbuseType:         "hacking",
				Decision:          "report",
				AbuseIPDBReported: true,
				Timestamp:         now.Add(-1 * time.Minute),
			},
			{
				EvidenceID: "ev-cs-1",
				Source:     "crowdsec_waf",
				IP:         "5.6.7.8",
				Decision:   "report_pending",
				Timestamp:  now.Add(-2 * time.Minute),
			},
		},
	}

	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"cloudflare_waf", "crowdsec_waf", "1.2.3.4", "5.6.7.8", "abuseipdb_reported"} {
		if !strings.Contains(body, want) {
			t.Errorf("timeline page missing %q", want)
		}
	}
}

func TestTimelineSourceFilter(t *testing.T) {
	now := time.Now().UTC()
	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{
				EvidenceID: "ev-waf-1",
				Source:     "cloudflare_waf",
				IP:         "9.10.11.12",
				Decision:   "report_pending",
				Timestamp:  now,
			},
		},
	}

	srv, auditSink, _ := newTestServer(t, nil)
	srv.evidence = store
	// Use a non-IP target that is unique enough not to appear elsewhere in the rendered page
	auditSink.Record("security_intelligence_lookup", map[string]string{
		"target": "unique-audit-target-xzqw",
		"source": "ui",
		"result": "neutral",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// WAF filter shows evidence but not audit entries
	req := httptest.NewRequest(http.MethodGet, "/timeline?source=waf", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "9.10.11.12") {
		t.Errorf("WAF filter should show WAF event IP: %s", body)
	}
	if strings.Contains(body, "unique-audit-target-xzqw") {
		t.Errorf("WAF filter should hide audit event target: %s", body)
	}

	// Audit filter shows audit entries but not WAF events
	req2 := httptest.NewRequest(http.MethodGet, "/timeline?source=audit", nil)
	req2.AddCookie(cookie)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)

	body2 := rr2.Body.String()
	if strings.Contains(body2, "9.10.11.12") {
		t.Errorf("audit filter should hide WAF event IP: %s", body2)
	}
	if !strings.Contains(body2, "unique-audit-target-xzqw") {
		t.Errorf("audit filter should show audit event target: %s", body2)
	}
}

func TestTimelineMergeOrder(t *testing.T) {
	base := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "ev-old", Source: "cloudflare_waf", IP: "old-ip", Decision: "report_pending", Timestamp: base.Add(-10 * time.Minute)},
			{EvidenceID: "ev-new", Source: "cloudflare_waf", IP: "new-ip", Decision: "report_pending", Timestamp: base.Add(5 * time.Minute)},
		},
	}

	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store

	events := srv.allTimelineEvents(context.Background())

	// new-ip must appear before old-ip (newest first)
	newIdx, oldIdx := -1, -1
	for i, e := range events {
		if e.Target == "new-ip" {
			newIdx = i
		}
		if e.Target == "old-ip" {
			oldIdx = i
		}
	}
	if newIdx < 0 || oldIdx < 0 {
		t.Fatalf("expected both IPs in timeline, got %+v", events)
	}
	if newIdx >= oldIdx {
		t.Errorf("newer event (idx %d) should appear before older event (idx %d)", newIdx, oldIdx)
	}
}

func TestTimelineFiltersAndExportsReadOnlyEvents(t *testing.T) {
	srv, audit, _ := newTestServer(t, nil)
	audit.Record("security_intelligence_lookup", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "203.0.113.4",
		"result":         "neutral",
		"correlation_id": "corr-1",
		"event_id":       "evt-1",
		"authorization":  "Bearer super-secret-token",
	})
	audit.Record("trusted_networks_export", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "trusted-networks",
		"result":         "read-only",
		"correlation_id": "corr-2",
		"event_id":       "evt-2",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/timeline?q=security&action=security_intelligence_lookup&format=json", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected JSON export, got %q", ct)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"security_intelligence_lookup",
		"corr-1",
		"evt-1",
		"neutral",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("timeline JSON missing %q: %s", want, body)
		}
	}
	for _, secret := range []string{"super-secret-token", "ui-secret-value"} {
		if strings.Contains(body, secret) {
			t.Fatalf("timeline JSON leaked secret %q: %s", secret, body)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/timeline?format=csv", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("expected CSV export, got %q", ct)
	}
	body = rr.Body.String()
	if !strings.Contains(body, "timestamp,scope,event_type,severity") {
		t.Fatalf("timeline CSV missing header: %s", body)
	}
	if strings.Contains(body, "super-secret-token") || strings.Contains(body, "ui-secret-value") {
		t.Fatalf("timeline CSV leaked secret: %s", body)
	}
}
