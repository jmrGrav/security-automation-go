package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/detect"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// ---------------------------------------------------------------------------
// cfSentinelToken: presence check across cfg and credential store
// ---------------------------------------------------------------------------

func TestCFSentinelToken_FromConfig(t *testing.T) {
	srv := newCFTestServer(t, nil, "tok-from-cfg", "zone-from-cfg")
	if srv.cfSentinelToken() == "" {
		t.Error("expected non-empty sentinel when token is in cfg")
	}
}

func TestCFSentinelToken_FromCredentialStore(t *testing.T) {
	creds := &fakeCredentialStore{values: map[string]string{"cloudflare.api_token": "tok-in-store"}}
	srv := newCFTestServer(t, creds, "", "")
	if srv.cfSentinelToken() == "" {
		t.Error("expected non-empty sentinel when token is in credential store only")
	}
}

func TestCFSentinelToken_NeitherConfigured(t *testing.T) {
	srv := newCFTestServer(t, nil, "", "")
	if got := srv.cfSentinelToken(); got != "" {
		t.Errorf("expected empty sentinel when unconfigured, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// cfMaskedKey: display-safe masked value
// ---------------------------------------------------------------------------

func TestCFMaskedKey_FromConfig(t *testing.T) {
	srv := newCFTestServer(t, nil, "tok-from-cfg", "")
	key := srv.cfMaskedKey()
	if key == "missing" || key == "configured (encrypted)" {
		t.Errorf("expected a redacted token string, got %q", key)
	}
}

func TestCFMaskedKey_FromStore(t *testing.T) {
	creds := &fakeCredentialStore{values: map[string]string{"cloudflare.api_token": "tok-in-store"}}
	srv := newCFTestServer(t, creds, "", "")
	if got := srv.cfMaskedKey(); got != "configured (encrypted)" {
		t.Errorf("expected %q, got %q", "configured (encrypted)", got)
	}
}

func TestCFMaskedKey_Missing(t *testing.T) {
	srv := newCFTestServer(t, nil, "", "")
	if got := srv.cfMaskedKey(); got != "missing" {
		t.Errorf("expected %q, got %q", "missing", got)
	}
}

// ---------------------------------------------------------------------------
// openRestyDashboard helpers — pure functions
// ---------------------------------------------------------------------------

func TestOpenRestyDashboardLevel_Healthy(t *testing.T) {
	detectors := []detect.Result{{Name: "openresty", Installed: true, Healthy: true}}
	if got := openRestyDashboardLevel(detectors); got != "healthy" {
		t.Errorf("expected healthy, got %q", got)
	}
}

func TestOpenRestyDashboardLevel_InstalledButDown(t *testing.T) {
	detectors := []detect.Result{{Name: "openresty", Installed: true, Healthy: false}}
	if got := openRestyDashboardLevel(detectors); got != "degraded" {
		t.Errorf("expected degraded, got %q", got)
	}
}

func TestOpenRestyDashboardLevel_NotInstalled(t *testing.T) {
	detectors := []detect.Result{{Name: "openresty", Installed: false, Healthy: false}}
	if got := openRestyDashboardLevel(detectors); got != "disabled" {
		t.Errorf("expected disabled, got %q", got)
	}
}

func TestOpenRestyDashboardDetail_NginxLogMode(t *testing.T) {
	detectors := []detect.Result{{Name: "openresty", Installed: true, Healthy: true}}
	if got := openRestyDashboardDetail(detectors, ""); !strings.Contains(got, "nginx log mode") {
		t.Errorf("expected nginx log mode detail, got %q", got)
	}
}

func TestOpenRestyDashboardDetail_WAFEventsFileExists(t *testing.T) {
	eventsFile := t.TempDir() + "/events.jsonl"
	if err := os.WriteFile(eventsFile, []byte(""), 0644); err != nil {
		t.Fatalf("write events file: %v", err)
	}
	detectors := []detect.Result{{Name: "openresty", Installed: true, Healthy: true}}
	if got := openRestyDashboardDetail(detectors, eventsFile); !strings.Contains(got, "WAF events") {
		t.Errorf("expected WAF events detail when file exists, got %q", got)
	}
}

func TestOpenRestyDashboardDetail_WAFEventsFileMissing(t *testing.T) {
	detectors := []detect.Result{{Name: "openresty", Installed: true, Healthy: true}}
	if got := openRestyDashboardDetail(detectors, "/nonexistent/events.jsonl"); strings.Contains(got, "WAF events") {
		t.Errorf("must not claim WAF events when file does not exist, got %q", got)
	}
}

// ---------------------------------------------------------------------------
// Dashboard stub panels must not carry a warning badge
// ---------------------------------------------------------------------------

func TestDashboard_StubPanelsAreDisabled(t *testing.T) {
	srv := newCFTestServer(t, nil, "tok", "zone")
	view := srv.dashboardConsoleView(context.Background())
	for _, label := range []string{"HA / fencing"} {
		for _, item := range view.Statuses {
			if item.Label == label && item.Level == "warning" {
				t.Errorf("stub panel %q must not carry a warning badge", label)
			}
		}
	}
}

// TestDashboard_HAFencingReportsRealUnavailableState guards GitHub issue #89:
// the HA/fencing row used to hardcode Level: "disabled" with a misleading
// detail ("read-only UI shell") that didn't describe why. Since the HA
// subsystem (#108) was deleted as dead code and no HA/fencing config exists,
// the row must honestly report "unavailable" rather than a config-implying
// "disabled" state, with a detail that explains the real reason.
func TestDashboard_HAFencingReportsRealUnavailableState(t *testing.T) {
	srv := newCFTestServer(t, nil, "tok", "zone")
	view := srv.dashboardConsoleView(context.Background())
	for _, item := range view.Statuses {
		if item.Label != "HA / fencing" {
			continue
		}
		if item.Level != "unavailable" {
			t.Errorf("expected Level %q, got %q", "unavailable", item.Level)
		}
		if item.Detail == "read-only UI shell" || strings.TrimSpace(item.Detail) == "" {
			t.Errorf("expected a real detail explaining HA absence, got %q", item.Detail)
		}
		return
	}
	t.Fatal("HA / fencing status row not found")
}

// ---------------------------------------------------------------------------
// Dashboard reported total from evidence store
// ---------------------------------------------------------------------------

func TestDashboard_ReportedTotalFromEvidenceStore(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "a", Source: "cloudflare_waf", AbuseIPDBReported: true},
			{EvidenceID: "b", Source: "cloudflare_waf", AbuseIPDBReported: true},
			{EvidenceID: "c", Source: "crowdsec_waf", Suppressed: true},
		},
	}

	view := srv.dashboardConsoleView(context.Background())

	if !view.EvidenceWired {
		t.Fatal("EvidenceWired should be true when evidence store is set")
	}
	if view.ReportedTotal != 2 {
		t.Errorf("ReportedTotal: want 2, got %d", view.ReportedTotal)
	}
}

func TestDashboard_ReportedTotalZeroWhenEvidenceNotWired(t *testing.T) {
	srv := newCFTestServer(t, nil, "tok", "zone")
	// srv.evidence is nil — daemon not wired

	view := srv.dashboardConsoleView(context.Background())

	if view.EvidenceWired {
		t.Fatal("EvidenceWired should be false when evidence store is nil")
	}
	if view.ReportedTotal != 0 {
		t.Errorf("ReportedTotal should be 0 when not wired, got %d", view.ReportedTotal)
	}
}

func TestDashboard_ReportedTotalAppearsInPage(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "x", Source: "cloudflare_waf", AbuseIPDBReported: true},
			{EvidenceID: "y", Source: "cloudflare_waf", AbuseIPDBReported: true},
			{EvidenceID: "z", Source: "cloudflare_waf", AbuseIPDBReported: true},
		},
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "AbuseIPDB Reported") {
		t.Errorf("dashboard should show AbuseIPDB Reported widget: %s", body)
	}
	if !strings.Contains(body, "3") {
		t.Errorf("dashboard should show reported count 3: %s", body)
	}
	if !strings.Contains(body, `/evidence?filter=reported`) {
		t.Errorf("dashboard reported widget should link to /evidence?filter=reported: %s", body)
	}
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

func newCFTestServer(t *testing.T, creds CredentialStorer, cfToken, cfZone string) *Server {
	t.Helper()
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.UI.Enabled = true
	cfg.UI.Addr = "127.0.0.1:0"
	cfg.UI.SecretFile = dataDir + "/ui-secrets.local"
	cfg.UI.ProviderStateFile = dataDir + "/ai-providers.env"
	cfg.StateDir = dataDir
	cfg.Cloudflare.APIToken = cfToken
	cfg.Cloudflare.ZoneID = cfZone
	store := &fakeGateStore{settings: map[string]string{}}
	_ = store.MarkComplete(nil)
	srv, err := NewServer(cfg, Options{
		SetupStore:      store,
		CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}
