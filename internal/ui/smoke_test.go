//go:build smoke

package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Smoke tests verify end-to-end UI flows using in-process fixtures only.
// Run with: go test -tags=smoke ./internal/ui/...
// No real Cloudflare/CrowdSec calls are made; all external dependencies are
// satisfied by the test config seeded in newTestServer.

func TestSmoke_ServerBoots(t *testing.T) {
	_, _, _ = newTestServer(t, nil)
	// newTestServer calls t.Fatalf on failure, so reaching here means success.
}

func TestSmoke_ProtectedRouteRejectsAnonymous(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	for _, path := range []string{"/", "/health", "/audit", "/forensic", "/providers"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusFound {
			t.Errorf("GET %s: expected redirect (302), got %d", path, rr.Code)
			continue
		}
		if loc := rr.Header().Get("Location"); loc != "/login" && loc != "/setup/step/1" {
			t.Errorf("GET %s: expected redirect to /login or /setup, got %q", path, loc)
		}
	}
}

func TestSmoke_SetupWizardAccessible(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/setup/step/1", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	// Before setup is complete, step 1 returns 200 (the wizard form).
	if rr.Code != http.StatusOK {
		t.Fatalf("GET /setup/step/1: expected 200, got %d", rr.Code)
	}
}

func TestSmoke_LoginSucceeds(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "smoke-secret",
	})

	cookie := loginCookie(t, srv, "smoke-secret")
	if cookie == nil {
		t.Fatal("expected session cookie after login")
	}
	if !cookie.HttpOnly {
		t.Error("session cookie must be HttpOnly")
	}
}

func TestSmoke_WrongPasswordRejected(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "smoke-secret",
	})

	req := httptest.NewRequest(http.MethodPost, "/login",
		strings.NewReader("secret=wrong-secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code == http.StatusFound {
		loc := rr.Header().Get("Location")
		if loc == "/" || loc == "" {
			t.Error("wrong password should not redirect to dashboard")
		}
	}
}

func TestSmoke_AuthenticatedDashboardReachable(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "smoke-secret",
	})
	cookie := loginCookie(t, srv, "smoke-secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("authenticated GET /: expected 200, got %d", rr.Code)
	}
}

func TestSmoke_HealthEndpointReachable(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "smoke-secret",
	})
	cookie := loginCookie(t, srv, "smoke-secret")

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code == http.StatusInternalServerError {
		t.Fatalf("GET /health returned 500: %s", rr.Body.String())
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("authenticated GET /health: expected 200, got %d", rr.Code)
	}
}

func TestSmoke_DryRunDoesNotMutateProviders(t *testing.T) {
	// Verify that POST mutations require CSRF and do not silently succeed without it.
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "smoke-secret",
	})
	cookie := loginCookie(t, srv, "smoke-secret")

	// Attempt to ban an IP without a CSRF token — must not succeed.
	req := httptest.NewRequest(http.MethodPost, "/actions/cloudflare/ban",
		strings.NewReader("ip=1.2.3.4&reason=smoke"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code == http.StatusOK || rr.Code == http.StatusAccepted {
		t.Errorf("POST /actions/cloudflare/ban without CSRF token should not succeed, got %d", rr.Code)
	}
}
