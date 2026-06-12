package ui

import (
	"os"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/detect"
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
	view := srv.dashboardConsoleView()
	for _, label := range []string{"HA / fencing", "Replay", "Recovery"} {
		for _, item := range view.Statuses {
			if item.Label == label && item.Level == "warning" {
				t.Errorf("stub panel %q must not carry a warning badge", label)
			}
		}
	}
}

func TestWorkflowPages_StubBadgesAreDisabled(t *testing.T) {
	srv := newCFTestServer(t, nil, "tok", "zone")
	for _, tc := range []struct {
		name   string
		badges []StatusItem
	}{
		{"replay", srv.replayView().Badges},
		{"drift", srv.driftView().Badges},
	} {
		for _, b := range tc.badges {
			if b.Level == "warning" {
				t.Errorf("%s page badge %q must not carry warning level", tc.name, b.Label)
			}
		}
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
