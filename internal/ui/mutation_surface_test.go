package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/ui/auth"
)

func TestMutationSurface_CSRFAndMethodEnforcement(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{"UI_SECRET": "test-secret"})
	
	// Initialize admin password file so it doesn't force change
	passwordFile := srv.cfg.UI.AdminPasswordFile
	if _, err := auth.InitializeBootstrapPassword(passwordFile); err != nil {
		t.Fatalf("failed to init bootstrap password: %v", err)
	}
	if err := auth.ClearBootstrapState(passwordFile); err != nil {
		t.Fatalf("failed to clear bootstrap state: %v", err)
	}

	cookie := loginCookie(t, srv, "test-secret")
	csrfToken := srv.csrfTokenFor(cookie.Value)

	routes := []struct {
		method string
		path   string
		body   string
	}{
		{"POST", "/ui/settings/password/change", `{"current_password":"a","new_password":"b","confirm_password":"b"}`},
		{"POST", "/admin/providers/openai/key", "confirm_replace=yes&new_api_key=sk-123"},
		{"POST", "/admin/providers/openai/test", ""},
		{"POST", "/admin/providers/openai/enable", ""},
		{"POST", "/admin/providers/openai/disable", ""},
		{"POST", "/forensic", "ip=1.2.3.4"},
		{"POST", "/intelligence", "ip=1.2.3.4"},
		{"POST", "/actions/cloudflare/ban", "ip=1.2.3.4"},
		{"POST", "/ui/ai/explain", `{"subject_type":"provider","subject_id":"openai","provider_preference":"auto"}`},
		// logout must be last: a successful POST /logout invalidates the session,
		// which would cause all subsequent subtests to get 302 instead of 403.
		{"POST", "/logout", ""},
	}

	for _, tt := range routes {
		t.Run(tt.method+" "+tt.path, func(t *testing.T) {
			// 1. Missing CSRF => 403
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if strings.HasPrefix(tt.body, "{") {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("missing CSRF: expected 403, got %d", rr.Code)
			}

			// 2. Invalid CSRF => 403
			req = httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if strings.HasPrefix(tt.body, "{") {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.AddCookie(cookie)
			req.Header.Set("X-CSRF-Token", "invalid")
			rr = httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusForbidden {
				t.Errorf("invalid CSRF: expected 403, got %d", rr.Code)
			}

			// 3. Valid CSRF => Should not be 403 (might be 200, 302, 303, 400 etc but not 403 CSRF error)
			req = httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.body))
			if strings.HasPrefix(tt.body, "{") {
				req.Header.Set("Content-Type", "application/json")
			} else {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			req.AddCookie(cookie)
			req.Header.Set("X-CSRF-Token", csrfToken)
			rr = httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			// "csrf required" is the literal error text our handlers return on CSRF failure.
			// Don't use a broader match like "csrf" — provider pages embed csrf_token in form
			// values and would falsely trigger if the handler returns 403 for other reasons.
			if rr.Code == http.StatusForbidden && strings.Contains(rr.Body.String(), "csrf required") {
				t.Errorf("valid CSRF rejected: %s", rr.Body.String())
			}

			// 4. Wrong Method (GET) => 404 or 405 (depending on mux and if there is a GET handler)
			// For forensic/intelligence, GET is forensic page, so we check if it's read-only.
			if tt.path != "/forensic" && tt.path != "/intelligence" {
				req = httptest.NewRequest(http.MethodGet, tt.path, nil)
				req.AddCookie(cookie)
				rr = httptest.NewRecorder()
				srv.Handler().ServeHTTP(rr, req)
				// Mux for POST-only routes will return 405 or 404
				if rr.Code == http.StatusOK && tt.method == "POST" {
					// Check if it's the dashboard or some other page
					if !strings.Contains(rr.Body.String(), "Dashboard") && !strings.Contains(rr.Body.String(), "About") {
						t.Errorf("GET accepted for POST-only route %s", tt.path)
					}
				}
			}
		})
	}
}
