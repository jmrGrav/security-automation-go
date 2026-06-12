package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/health"
)

func TestHandleHealthJSON_ReturnsJSON(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)

	sessionToken := generateSessionToken()
	srv.mu.Lock()
	srv.sessions[sessionToken] = time.Now().Add(sessionTTL)
	srv.mu.Unlock()

	req := httptest.NewRequest("GET", "/health/json", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()
	srv.handleHealthJSON(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	body := w.Body.String()
	if !strings.Contains(body, `"health"`) {
		t.Error("expected 'health' key in JSON response")
	}
	if !strings.Contains(body, `"detection"`) {
		t.Error("expected 'detection' key in JSON response")
	}
	if !strings.Contains(body, `"generated_at"`) {
		t.Error("expected 'generated_at' key in JSON response")
	}
}

func TestHandleHealthPage_RendersWithoutPanic(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)

	sessionToken := generateSessionToken()
	srv.mu.Lock()
	srv.sessions[sessionToken] = time.Now().Add(sessionTTL)
	srv.mu.Unlock()

	req := httptest.NewRequest("GET", "/health", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()
	srv.handleHealthPage(w, req)

	if w.Code == http.StatusInternalServerError {
		t.Errorf("unexpected 500: %s", w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, "Health Center") {
		t.Error("expected 'Health Center' in page body")
	}
}

func TestHealthPage_ContainsSummaryAndButton(t *testing.T) {
	checks := []health.Check{
		{Name: "sqlite", Status: health.Green, Reason: "ok"},
		{Name: "disk", Status: health.Yellow, Reason: "low"},
		{Name: "cloudflare", Status: health.Red, Reason: "missing"},
	}
	view := healthPageView{
		Checks:     checks,
		ReportTime: "2026-06-07T00:00:00Z",
	}
	comp := HealthPage(view, "test-csrf")
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	for _, want := range []string{"Health Center", "GREEN", "YELLOW", "RED", "Run Full Diagnostic", "Download Support Bundle"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in page", want)
		}
	}
}

// ---------------------------------------------------------------------------
// OpenResty runbook panel
// ---------------------------------------------------------------------------

func TestOpenRestyRunbook_ShownWhenEventsFileMissing(t *testing.T) {
	view := healthPageView{
		Detectors: []detect.Result{
			{
				Name:       "openresty",
				Installed:  true,
				Configured: true,
				Healthy:    true,
				Details: map[string]string{
					"events_file":  "/var/lib/security-automation-go/events.jsonl",
					"events_exist": "missing",
				},
			},
		},
		ReportTime: "2026-06-12T00:00:00Z",
	}
	comp := HealthPage(view, "csrf")
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	if !strings.Contains(body, "OpenResty Runbook") {
		t.Error("expected OpenResty Runbook panel when events file is missing")
	}
	if !strings.Contains(body, "Events file missing") {
		t.Error("expected 'Events file missing' badge")
	}
}

func TestOpenRestyRunbook_ShownWhenStuckProcessing(t *testing.T) {
	view := healthPageView{
		Detectors: []detect.Result{
			{
				Name:       "openresty",
				Installed:  true,
				Configured: true,
				Healthy:    true,
				Details: map[string]string{
					"events_file":      "/var/lib/security-automation-go/events.jsonl",
					"events_exist":     "present",
					"events_age":       "2m0s ago",
					"stuck_processing": "present (prior ingestion may be lost)",
				},
			},
		},
		ReportTime: "2026-06-12T00:00:00Z",
	}
	comp := HealthPage(view, "csrf")
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	if !strings.Contains(body, "OpenResty Runbook") {
		t.Error("expected OpenResty Runbook panel when stuck processing file exists")
	}
	if !strings.Contains(body, "Stuck processing file") {
		t.Error("expected stuck processing detail in runbook")
	}
}

func TestOpenRestyRunbook_HiddenWhenHealthy(t *testing.T) {
	view := healthPageView{
		Detectors: []detect.Result{
			{
				Name:       "openresty",
				Installed:  true,
				Configured: true,
				Healthy:    true,
				Details: map[string]string{
					"events_file":  "/var/lib/security-automation-go/events.jsonl",
					"events_exist": "present",
					"events_age":   "5s ago",
				},
			},
		},
		ReportTime: "2026-06-12T00:00:00Z",
	}
	comp := HealthPage(view, "csrf")
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	if strings.Contains(body, "OpenResty Runbook") {
		t.Error("runbook panel should not appear when events file is fresh and no issues")
	}
}

func TestOpenRestyRunbook_ShownWhenStale(t *testing.T) {
	view := healthPageView{
		Detectors: []detect.Result{
			{
				Name:       "openresty",
				Installed:  true,
				Configured: true,
				Healthy:    true,
				Details: map[string]string{
					"events_file":  "/var/lib/security-automation-go/events.jsonl",
					"events_exist": "present",
					"events_age":   "2h0m0s ago",
				},
			},
		},
		ReportTime: "2026-06-12T00:00:00Z",
	}
	comp := HealthPage(view, "csrf")
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	if !strings.Contains(body, "OpenResty Runbook") {
		t.Error("expected OpenResty Runbook panel when events file is stale (>30min)")
	}
	if !strings.Contains(body, "stale") {
		t.Error("expected 'stale' text in runbook for old events file")
	}
}

func TestOpenRestyRunbook_NotShownWhenNotConfigured(t *testing.T) {
	view := healthPageView{
		Detectors: []detect.Result{
			{
				Name:       "openresty",
				Installed:  false,
				Configured: false,
				Healthy:    false,
				Details:    map[string]string{},
			},
		},
		ReportTime: "2026-06-12T00:00:00Z",
	}
	comp := HealthPage(view, "csrf")
	w := httptest.NewRecorder()
	_ = comp.Render(nil, w)
	body := w.Body.String()

	if strings.Contains(body, "OpenResty Runbook") {
		t.Error("runbook panel should not appear when openresty not configured")
	}
}

func TestHealthLevelClass(t *testing.T) {
	if healthLevelClass(health.Green) != "healthy" {
		t.Error("expected 'healthy' for Green")
	}
	if healthLevelClass(health.Yellow) != "warning" {
		t.Error("expected 'warning' for Yellow")
	}
	if healthLevelClass(health.Red) != "error" {
		t.Error("expected 'error' for Red")
	}
}
