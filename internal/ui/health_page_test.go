package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
