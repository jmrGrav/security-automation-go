package ui

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/security/audit"
)

func TestFileAuditSinkWritesEntriesAndRedactsSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ui-audit.log")

	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink failed: %v", err)
	}
	sink.Record("security_intelligence_lookup", map[string]string{
		"actor":            "local",
		"source":           "ui",
		"target":           "203.0.113.10",
		"result":           "neutral",
		"correlation_id":   "corr-1",
		"event_id":         "evt-123",
		"authorization":    "Bearer super-secret-token",
		"cookie":           "session=top-secret",
		"api_key":          "vt-secret-key",
		"source_detail":    "manual lookup",
		"rate_limit_count": "0",
	})

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read audit log failed: %v", err)
	}
	body := string(raw)
	for _, want := range []string{
		"security_intelligence_lookup",
		"actor=local",
		"source=ui",
		"event_id=evt-123",
		"correlation_id=corr-1",
		"authorization=[REDACTED]",
		"cookie=[REDACTED]",
		"api_key=[REDACTED]",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit log missing %q: %s", want, body)
		}
	}
	for _, secret := range []string{"super-secret-token", "session=top-secret", "vt-secret-key"} {
		if strings.Contains(body, secret) {
			t.Fatalf("audit log leaked secret %q: %s", secret, body)
		}
	}
}

func TestAuditTrailPageRendersForensicTable(t *testing.T) {
	view := AuditTrailView{
		Entries: []audit.AuditEntry{
			{
				Timestamp:    "2026-06-01T09:01:00Z",
				ActorSession: "ui",
				Source:       "provider-health",
				Action:       "provider_test_lookup",
				Target:       "Cloudflare",
				Result:       "dry-run",
				Correlation:  "corr-7",
				EventID:      "evt-7",
			},
			{
				Timestamp:    "2026-06-01T09:02:00Z",
				ActorSession: "operator",
				Source:       "trusted-networks",
				Action:       "trusted_networks_view",
				Target:       "registry",
				Result:       "read-only",
				Correlation:  "corr-8",
			},
			{
				Timestamp:    "2026-06-01T09:02:30Z",
				ActorSession: "operator",
				Source:       "trusted-networks",
				Action:       "trusted_networks_export",
				Target:       "registry",
				Result:       "read-only",
				Correlation:  "corr-8b",
			},
			{
				Timestamp:    "2026-06-01T09:02:45Z",
				ActorSession: "operator",
				Source:       "trusted-networks",
				Action:       "trusted_networks_refresh_dry_run",
				Target:       "registry",
				Result:       "dry-run",
				Correlation:  "corr-8c",
			},
			{
				Timestamp:    "2026-06-01T09:03:00Z",
				ActorSession: "intelligence",
				Action:       "security_intelligence_lookup",
				Target:       "203.0.113.10",
				Result:       "neutral",
				Correlation:  "corr-9",
				EventID:      "evt-9",
			},
		},
	}

	var buf bytes.Buffer
	if err := AuditTrailPage(view, "csrf-token").Render(context.Background(), &buf); err != nil {
		t.Fatalf("render audit trail page: %v", err)
	}
	body := buf.String()

	for _, want := range []string{
		`data-live-shell="audit"`,
		`data-live-search-form="true"`,
		"timestamp",
		"actor/source",
		"action",
		"target",
		"result",
		"correlation id",
		"event id",
		"provider_test_lookup",
		"trusted_networks_view",
		"trusted_networks_export",
		"trusted_networks_refresh_dry_run",
		"security_intelligence_lookup",
		"evt-7",
		"corr-8c",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("audit page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, `action="/actions/`) || strings.Contains(body, "allowlist") || strings.Contains(body, "cloudflare_ban_preview") || strings.Contains(body, "mutation") {
		t.Fatalf("audit trail page must not render mutation controls: %s", body)
	}
}

func TestAuditTrailPageEmptyState(t *testing.T) {
	var buf bytes.Buffer
	if err := AuditTrailPage(AuditTrailView{}, "csrf-token").Render(context.Background(), &buf); err != nil {
		t.Fatalf("render audit trail page: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "No audit events yet") {
		t.Fatalf("audit page should render empty state, got %s", body)
	}
	if !strings.Contains(body, `data-live-shell="audit"`) || !strings.Contains(body, `data-live-search-form="true"`) {
		t.Fatalf("audit page should expose live shell and search form, got %s", body)
	}
	if !strings.Contains(body, "UI lookups and operator actions will appear here") {
		t.Fatalf("audit page should explain empty state, got %s", body)
	}
	if strings.Contains(body, "<table>") {
		t.Fatalf("empty audit page must not render a table, got %s", body)
	}
}

func TestRenderV2AuditTrailPageEmptyStateIsOperational(t *testing.T) {
	out := renderV2AuditTrailPage(AuditTrailView{RefreshURL: "/v2/audit"}, "csrf-token")
	for _, want := range []string{
		"Audit",
		"No audit events yet",
		"Recent activity",
		"Suggested actions",
		"Recent searches",
		"Quick links",
		"/v2/timeline",
		"/v2/providers",
		"/v2/health",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("v2 audit empty state missing %q: %s", want, out)
		}
	}
}

func TestFileAuditSinkEntriesContextHonorsCancellation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ui-audit.log")

	sink, err := NewFileAuditSink(path)
	if err != nil {
		t.Fatalf("NewFileAuditSink failed: %v", err)
	}
	sink.Record("audit_event", map[string]string{"target": "203.0.113.10"})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := sink.EntriesContext(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context cancellation, got %v", err)
	}
}

func TestLoginAndLogoutAuditEntriesIncludeUsefulMetadata(t *testing.T) {
	srv, auditSink, _ := newTestServer(t, nil)

	cookie := loginCookie(t, srv, "test-password-123!@#")
	entries := auditSink.Entries()
	if len(entries) == 0 {
		t.Fatal("expected login to emit an audit entry")
	}

	loginEntry := entries[len(entries)-1]
	if loginEntry.Action != "login_success" {
		t.Fatalf("expected login_success, got %+v", loginEntry)
	}
	if loginEntry.Target == "" || loginEntry.Target == "unknown" {
		t.Fatalf("expected useful login target, got %+v", loginEntry)
	}
	if loginEntry.Result != "success" {
		t.Fatalf("expected login success result, got %+v", loginEntry)
	}
	if loginEntry.EventID == "" {
		t.Fatalf("expected login event_id, got %+v", loginEntry)
	}
	if loginEntry.Correlation != loginEntry.EventID {
		t.Fatalf("expected login correlation/event_id parity, got %+v", loginEntry)
	}

	req := httptest.NewRequest(http.MethodPost, "/logout", nil)
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected logout redirect, got %d: %s", rr.Code, rr.Body.String())
	}

	entries = auditSink.Entries()
	logoutEntry := entries[len(entries)-1]
	if logoutEntry.Action != "logout" {
		t.Fatalf("expected logout entry, got %+v", logoutEntry)
	}
	if logoutEntry.Target == "" || logoutEntry.Target == "unknown" {
		t.Fatalf("expected useful logout target, got %+v", logoutEntry)
	}
	if logoutEntry.Result != "success" {
		t.Fatalf("expected logout success result, got %+v", logoutEntry)
	}
	if logoutEntry.EventID == "" {
		t.Fatalf("expected logout event_id, got %+v", logoutEntry)
	}
	if logoutEntry.Correlation != logoutEntry.EventID {
		t.Fatalf("expected logout correlation/event_id parity, got %+v", logoutEntry)
	}
}

func TestAuditTrailPageFallsBackToCorrelationForLegacyEventID(t *testing.T) {
	view := AuditTrailView{
		Entries: []audit.AuditEntry{
			{
				Timestamp:    "2026-06-01T09:01:00Z",
				ActorSession: "local",
				Source:       "ui",
				Action:       "provider_test",
				Target:       "cloudflare",
				Result:       "ready",
				Correlation:  "corr-legacy",
			},
		},
	}

	var buf bytes.Buffer
	if err := AuditTrailPage(view, "csrf-token").Render(context.Background(), &buf); err != nil {
		t.Fatalf("render audit trail page: %v", err)
	}
	body := buf.String()

	if strings.Count(body, "corr-legacy") < 2 {
		t.Fatalf("expected legacy correlation to populate event id fallback, got %s", body)
	}
	if strings.Contains(body, ">unknown<") {
		t.Fatalf("legacy correlation row should not render unknown event id, got %s", body)
	}
}
