package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
