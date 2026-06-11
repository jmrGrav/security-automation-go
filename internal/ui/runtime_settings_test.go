package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestHandleRuntimeSettings_GET(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/settings/runtime", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	for _, want := range []string{
		"cs_poller_enabled",
		"cloudflare_mutations_enabled",
		"abuseipdb_enabled",
		"betterstack_enabled",
		"Runtime Settings",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("expected body to contain %q", want)
		}
	}
}

func TestHandleRuntimeSettings_GET_SavedBanner(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/settings/runtime?saved=1", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	if !strings.Contains(rr.Body.String(), "Settings saved") {
		t.Error("expected 'Settings saved' banner when ?saved=1")
	}
}

func TestHandleRuntimeSettingsPost_SavesFlags(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	form := url.Values{
		"csrf_token":                   {srv.csrfTokenFor(cookie.Value)},
		"cs_poller_enabled":            {"true"},
		"cloudflare_mutations_enabled": {"true"},
		"abuseipdb_enabled":            {"true"},
		"betterstack_enabled":          {"true"},
	}

	req := httptest.NewRequest(http.MethodPost, "/settings/runtime", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d: %s", rr.Code, rr.Body.String())
	}

	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "/settings/runtime") {
		t.Errorf("expected redirect to /settings/runtime, got %q", loc)
	}

	// Verify flags were persisted via the base SetupStorer interface (GetSetting)
	ctx := context.Background()
	for _, key := range []string{"cs_poller_enabled", "cloudflare_mutations_enabled", "abuseipdb_enabled", "betterstack_enabled"} {
		val, ok, err := srv.setupStore.GetSetting(ctx, key)
		if err != nil {
			t.Errorf("GetSetting(%q): %v", key, err)
			continue
		}
		if !ok {
			t.Errorf("expected key %q to be present in store", key)
			continue
		}
		if val != "true" {
			t.Errorf("expected %q = %q, got %q", key, "true", val)
		}
	}
}

func TestHandleRuntimeSettingsPost_FlagsOff(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// First set all flags to true
	ctx := context.Background()
	for _, key := range []string{"cs_poller_enabled", "cloudflare_mutations_enabled", "abuseipdb_enabled", "betterstack_enabled"} {
		_ = srv.setupStore.SetSetting(ctx, key, "true")
	}

	// POST with no checkbox values (all off)
	form := url.Values{
		"csrf_token": {srv.csrfTokenFor(cookie.Value)},
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/runtime", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d: %s", rr.Code, rr.Body.String())
	}

	for _, key := range []string{"cs_poller_enabled", "cloudflare_mutations_enabled", "abuseipdb_enabled", "betterstack_enabled"} {
		val, ok, err := srv.setupStore.GetSetting(ctx, key)
		if err != nil {
			t.Errorf("GetSetting(%q): %v", key, err)
			continue
		}
		if !ok {
			t.Errorf("expected key %q to be present", key)
			continue
		}
		if val != "false" {
			t.Errorf("expected %q = %q, got %q", key, "false", val)
		}
	}
}

func TestHandleRuntimeSettingsPost_CSRFRequired(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	form := url.Values{
		"cs_poller_enabled": {"true"},
	}
	req := httptest.NewRequest(http.MethodPost, "/settings/runtime", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	// No CSRF token
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for missing CSRF, got %d", rr.Code)
	}
}

func TestHandleRuntimeSettings_RequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/settings/runtime", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	// Should redirect to login
	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect for unauthenticated request, got %d", rr.Code)
	}
}
