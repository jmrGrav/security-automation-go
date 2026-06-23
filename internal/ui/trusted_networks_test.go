package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/trustednetworks"
)

func TestTrustedNetworks_RequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodGet, "/trusted-networks", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect to login, got %d", rr.Code)
	}
	if loc := rr.Header().Get("Location"); loc != "/login" {
		t.Fatalf("expected /login redirect, got %q", loc)
	}
}

func TestTrustedNetworks_RenderRegistryEntries(t *testing.T) {
	srv, audit, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/trusted-networks", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"Cloudflare",
		"Google",
		"Microsoft/Bing",
		"BetterStack",
		"UptimeRobot/Pingdom",
		"OpenAI GPTBot",
		"OpenAI SearchBot",
		"GitHub Copilot",
		"Anthropic",
		"OpenAI ChatGPT-User",
		"no hard ban",
		"CF: awaiting first sync",
		"CS: awaiting helper status",
		"manual review required / too volatile",
		// Table headers
		"Name", "Kind", "CIDRs", "Protection", "Allowlist", "Status",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("trusted networks page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "auto-allowlist") {
		t.Fatalf("page must not render auto-allowlist action: %s", body)
	}
	if strings.Contains(body, "ui-secret-value") {
		t.Fatalf("page leaked secret: %s", body)
	}
	if !strings.Contains(audit.String(), "trusted_networks_view") {
		t.Fatalf("expected trusted_networks_view audit event, got: %s", audit.String())
	}
}

// TestTrustedNetworks_ShadowModeNeverShowsSynced guards the core safety
// invariant: in shadow mode the registry never mutates a spoke, so even
// when a CIDR happens to already be present remotely (AlreadySynced), the
// page must never claim "synced" with a misleading implication of active
// enforcement — it must say "pending (shadow mode)" so an operator cannot
// mistake passive detection for an active push.
func TestTrustedNetworks_ShadowModeNeverShowsSynced(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cache := trustednetworks.NewReportCache()
	cache.Set(trustednetworks.SyncReport{
		Mode: "shadow",
		Cloudflare: trustednetworks.SpokeResult{
			Enabled: true,
			// Deliberately empty AlreadySynced/Pushed: shadow mode means
			// nothing has been pushed, regardless of remote state.
		},
		CrowdSec: trustednetworks.SpokeResult{Enabled: true},
	})
	srv.trustedNetworksCache = cache
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/trusted-networks", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "sync: shadow") {
		t.Fatalf("expected shadow-mode sync banner, got: %s", body)
	}
	if strings.Contains(body, "CF: synced") || strings.Contains(body, "CS: synced") {
		t.Fatalf("shadow mode must never report a CIDR as synced: %s", body)
	}
	if !strings.Contains(body, "pending (shadow mode)") {
		t.Fatalf("expected pending (shadow mode) status, got: %s", body)
	}
}

// TestTrustedNetworks_EnforceModeReflectsActualSyncState verifies the
// Allowlisted flag and per-spoke labels only flip to "synced" once both
// spokes' SpokeResult actually contains every CIDR for that organization —
// not merely because enforce mode is configured.
func TestTrustedNetworks_EnforceModeReflectsActualSyncState(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cache := trustednetworks.NewReportCache()
	cache.Set(trustednetworks.SyncReport{
		Mode: "enforce",
		Cloudflare: trustednetworks.SpokeResult{
			Enabled:       true,
			AlreadySynced: []string{"160.79.104.0/21", "2607:6bc0::/48"}, // Anthropic's CIDRs
		},
		CrowdSec: trustednetworks.SpokeResult{
			Enabled: true,
			Pushed:  []string{"160.79.104.0/21"}, // partial: missing the IPv6 range
		},
	})
	srv.trustedNetworksCache = cache
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/trusted-networks", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "sync: enforce") {
		t.Fatalf("expected enforce-mode sync banner, got: %s", body)
	}
	if !strings.Contains(body, "CF: synced") {
		t.Fatalf("expected Cloudflare spoke to report fully synced for Anthropic, got: %s", body)
	}
	// CrowdSec is only partially synced (missing the IPv6 range), so it must
	// report "pending", never "synced" — partial sync must not be conflated
	// with full sync.
	if !strings.Contains(body, "CS: pending") {
		t.Fatalf("expected CrowdSec spoke to report pending (partial sync), got: %s", body)
	}
}

// TestTrustedNetworks_CrowdSecHelperStatusRendered guards the fix for the
// gap documented in cmd/cf-sync/trustednetworks_wiring.go: the daemon's own
// CrowdSec spoke is always disabled (it cannot read CrowdSec's root-only
// credentials file), so the page must read the root-owned cf-allowlist-sync
// helper's persisted status instead of perpetually claiming "disabled".
func TestTrustedNetworks_CrowdSecHelperStatusRendered(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	statusStore := sqlite.NewCrowdSecAllowlistStatusStore(db)

	allowlistName := srv.cfg.CrowdSec.AllowlistName
	if allowlistName == "" {
		t.Fatal("expected a default CrowdSec allowlist name in test config")
	}
	if err := statusStore.PutCrowdSecAllowlistStatus(context.Background(), trustednetworks.CrowdSecAllowlistStatus{
		AllowlistName: allowlistName,
		Configured:    true,
		AuthOK:        true,
		LastSyncAt:    time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		DesiredCount:  5,
		CurrentCount:  5,
		DriftCount:    0,
		Mode:          "enforce",
	}); err != nil {
		t.Fatalf("PutCrowdSecAllowlistStatus: %v", err)
	}
	srv.crowdSecStatusStore = statusStore

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/trusted-networks", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"crowdsec helper: ok",
		"desired: 5",
		"current: 5",
		"CS: synced (helper)",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("trusted networks page missing %q: %s", want, body)
		}
	}
	if strings.Contains(body, "awaiting helper status") {
		t.Fatalf("page should not claim helper status is unavailable once wired: %s", body)
	}
}

// TestTrustedNetworks_CrowdSecHelperErrorSurfaced confirms a failed helper
// reconcile pass (e.g. cscli auth failure) is surfaced as an error, not
// silently rendered as healthy.
func TestTrustedNetworks_CrowdSecHelperErrorSurfaced(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	statusStore := sqlite.NewCrowdSecAllowlistStatusStore(db)

	allowlistName := srv.cfg.CrowdSec.AllowlistName
	if err := statusStore.PutCrowdSecAllowlistStatus(context.Background(), trustednetworks.CrowdSecAllowlistStatus{
		AllowlistName: allowlistName,
		Configured:    true,
		AuthOK:        false,
		LastSyncAt:    time.Date(2026, 6, 20, 12, 0, 0, 0, time.UTC),
		LastError:     "cscli allowlists inspect: permission denied",
		Mode:          "enforce",
	}); err != nil {
		t.Fatalf("PutCrowdSecAllowlistStatus: %v", err)
	}
	srv.crowdSecStatusStore = statusStore

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/trusted-networks", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"crowdsec helper: error",
		"cscli allowlists inspect: permission denied",
		"CS: helper error",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("trusted networks page missing %q: %s", want, body)
		}
	}
}

func TestTrustedNetworks_ExportIsReadOnlyAndDeterministic(t *testing.T) {
	srv, audit, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	export := func() string {
		req := httptest.NewRequest(http.MethodGet, "/trusted-networks/export", nil)
		req.AddCookie(cookie)
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("expected export status 200, got %d", rr.Code)
		}
		if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
			t.Fatalf("expected text/plain export, got %q", ct)
		}
		return rr.Body.String()
	}

	first := export()
	second := export()

	for _, want := range []string{
		"Trusted Networks Registry Export",
		"[OpenAI GPTBot]",
		"organization=openai-gptbot",
		"cloudflare_whitelist=awaiting first sync",
		"allowlisted=false",
	} {
		if !strings.Contains(first, want) {
			t.Fatalf("export missing %q: %s", want, first)
		}
	}
	if first != second {
		t.Fatalf("export must be deterministic and read-only; first=%q second=%q", first, second)
	}
	if !strings.Contains(audit.String(), "trusted_networks_export") {
		t.Fatalf("expected trusted_networks_export audit event, got: %s", audit.String())
	}
}
