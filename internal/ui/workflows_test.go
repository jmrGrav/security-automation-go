package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkflowPagesRenderReadOnlySections(t *testing.T) {
	srv, _, _ := newTestServer(t, map[string]string{
		"UI_SECRET": "ui-secret-value",
	})
	cookie := loginCookie(t, srv, "ui-secret-value")

	cases := []struct {
		path string
		want []string
	}{
		{
			path: "/cloudflare/diff",
			want: []string{"Cloudflare Diff", "Desired state", "Observed state", "Missing resources", "Divergent resources", "Extra resources", "Drift summary", "Convergence summary", "read-only"},
		},
		{
			path: "/replay",
			want: []string{"Replay Center", "Checkpoints", "Snapshots", "Replay status", "Replay explain", "Consistency indicators", "unavailable"},
		},
		{
			path: "/recovery",
			want: []string{"Recovery Center", "Available snapshots", "Available checkpoints", "Last recovery", "Recovery validation", "Recovery signals", "unavailable"},
		},
		{
			path: "/drift",
			want: []string{"Drift Center", "Active drift", "Historical drift", "Oscillations", "Impacted scopes", "Ownership impact", "Convergence indicators", "unknown"},
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
		"UI_SECRET":          "ui-secret-value",
		"SPAMHAUS_API_KEY":   "spamhaus-secret",
		"VIRUSTOTAL_API_KEY": "virustotal-secret",
		"ABUSEIPDB_KEY":      "abuse-secret",
	})
	cookie := loginCookie(t, srv, "ui-secret-value")

	for _, path := range []string{"/cloudflare/diff", "/replay", "/recovery", "/drift", "/timeline"} {
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
