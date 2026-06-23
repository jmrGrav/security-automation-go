package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkflowPagesRenderReadOnlySections(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	cases := []struct {
		path string
		want []string
	}{
		{
			path: "/cloudflare/diff",
			want: []string{"Cloudflare Diff", "Desired state", "Observed state", "Missing resources", "Divergent resources", "Extra resources", "Drift summary", "Convergence summary", "read-only"},
		},
	}

	for _, tc := range cases {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)

		body := rr.Body.String()
		for _, want := range tc.want {
			if !strings.Contains(body, want) {
				t.Fatalf("%s missing %q: %s", tc.path, want, body)
			}
		}
		if strings.Contains(body, "coming soon") {
			t.Fatalf("%s should no longer render a coming-soon placeholder: %s", tc.path, body)
		}
	}
}

func TestWorkflowPagesDoNotLeakSecrets(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"SPAMHAUS_API_KEY":   "spamhaus-secret",
		"VIRUSTOTAL_API_KEY": "virustotal-secret",
		"ABUSEIPDB_KEY":      "abuse-secret",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	for _, path := range []string{"/cloudflare/diff", "/timeline"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)

		body := rr.Body.String()
		for _, secret := range []string{"spamhaus-secret", "virustotal-secret", "abuse-secret", "ui-secret-value"} {
			if strings.Contains(body, secret) {
				t.Fatalf("%s leaked secret %q: %s", path, secret, body)
			}
		}
	}
}

// TestRemovedShellPlaceholderRoutesAreGone guards issue #85: /replay,
// /recovery, /drift, and /deban were shell-only pages presenting
// future-state copy ("checkpoint store", "convergence projection", etc.)
// with zero backing data — their backing subsystems (replay, recovery, HA)
// were already deleted as dead code, and the drift engine that does exist
// in the daemon is not wired to the UI server at all. None of the four were
// reachable from navigation. Per the issue's own recommended fix ("remove
// the route and navigation entry until the workflow is implemented"), the
// routes were deleted outright rather than left presenting fake state. Since
// this app's root pattern ("GET /") catches any unmatched path and serves
// the dashboard rather than a 404, this test instead asserts the old
// placeholder/coming-soon copy no longer renders for any of these paths.
func TestRemovedShellPlaceholderRoutesAreGone(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	removedCopy := []string{
		"Replay Center", "Recovery Center", "Drift Center",
		"coming soon", "checkpoint store", "convergence projection",
		"reserved for preview, dry-run, and future execution",
	}

	for _, path := range []string{"/replay", "/recovery", "/drift", "/deban"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)

		body := rr.Body.String()
		for _, want := range removedCopy {
			if strings.Contains(body, want) {
				t.Errorf("%s: still renders removed placeholder copy %q", path, want)
			}
		}
	}
}
