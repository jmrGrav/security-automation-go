package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/banlifecycle"
	cfmodels "github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/config"
)

func TestCFSyncView_NotWired(t *testing.T) {
	s := &Server{}
	view := s.buildCFSyncView(context.Background())
	if view.Wired {
		t.Error("expected Wired=false when no banLifecycleStore is configured")
	}
	if view.Error != "" {
		t.Errorf("unexpected error: %s", view.Error)
	}
}

func TestCFSyncView_NoActivity(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.banLifecycleStore = &fakeBanLifecycleStore{}

	view := srv.buildCFSyncView(context.Background())
	if !view.Wired {
		t.Fatal("expected Wired=true")
	}
	if view.HasActivity {
		t.Error("expected HasActivity=false when store is empty")
	}
}

func TestCFSyncView_WithActivity(t *testing.T) {
	now := time.Now().UTC()
	store := &fakeBanLifecycleStore{entries: []banlifecycle.Entry{
		{IP: "1.2.3.4", Status: banlifecycle.StatusActive, CreatedAt: now},
		{IP: "5.6.7.8", Status: banlifecycle.StatusActive, CreatedAt: now.Add(-time.Hour)},
		{IP: "9.10.11.12", Status: banlifecycle.StatusExpiredCleaned, CreatedAt: now.Add(-2 * time.Hour)},
	}}
	srv, _, _ := newTestServer(t, nil)
	srv.banLifecycleStore = store

	view := srv.buildCFSyncView(context.Background())
	if !view.HasActivity {
		t.Fatal("expected HasActivity=true")
	}
	if view.ActiveCount != 3 {
		t.Errorf("expected ActiveCount=3 (fake Active() returns all entries), got %d", view.ActiveCount)
	}
	if view.StatusCounts[banlifecycle.StatusActive] != 2 {
		t.Errorf("expected 2 active-status entries, got %d", view.StatusCounts[banlifecycle.StatusActive])
	}
	if view.StatusCounts[banlifecycle.StatusExpiredCleaned] != 1 {
		t.Errorf("expected 1 expired_cleaned entry, got %d", view.StatusCounts[banlifecycle.StatusExpiredCleaned])
	}
	if !view.LastActivityAt.Equal(now) {
		t.Errorf("expected LastActivityAt=%v, got %v", now, view.LastActivityAt)
	}
}

func TestCFSyncView_StoreError(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.banLifecycleStore = &fakeBanLifecycleStore{err: errors.New("boom")}

	view := srv.buildCFSyncView(context.Background())
	if view.Error == "" {
		t.Error("expected an error to be surfaced")
	}
}

func TestCFSyncPage_RendersNotWired(t *testing.T) {
	view := CFSyncView{Wired: false}
	comp := CFSyncPage(view)
	w := httptest.NewRecorder()
	_ = comp.Render(context.Background(), w)
	body := w.Body.String()

	if !strings.Contains(body, "CF Ban Sync") {
		t.Error("expected page title in body")
	}
	if !strings.Contains(body, "not configured") {
		t.Error("expected not-configured message")
	}
}

func TestCFSyncPage_RendersNoActivity(t *testing.T) {
	view := CFSyncView{Wired: true, DryRun: true}
	comp := CFSyncPage(view)
	w := httptest.NewRecorder()
	_ = comp.Render(context.Background(), w)
	body := w.Body.String()

	if !strings.Contains(body, "DRY-RUN") {
		t.Error("expected DRY-RUN badge")
	}
	if !strings.Contains(body, "No Cloudflare-managed bans recorded yet") {
		t.Error("expected no-activity message")
	}
}

func TestCFSyncPage_RendersActivity(t *testing.T) {
	view := CFSyncView{
		Wired:          true,
		MutationsOn:    true,
		HasActivity:    true,
		ActiveCount:    7,
		StatusCounts:   map[string]int{banlifecycle.StatusActive: 7, banlifecycle.StatusExpiredCleaned: 3},
		SampleSize:     10,
		LastActivityAt: time.Now().UTC(),
	}
	comp := CFSyncPage(view)
	w := httptest.NewRecorder()
	_ = comp.Render(context.Background(), w)
	body := w.Body.String()

	if !strings.Contains(body, "MUTATIONS ON") {
		t.Error("expected MUTATIONS ON badge")
	}
	if !strings.Contains(body, ">7<") {
		t.Error("expected active count in body")
	}
	if !strings.Contains(body, "/ban-lifecycle") {
		t.Error("expected link to /ban-lifecycle")
	}
}

// TestFetchCFRuleInventory_NotWiredWithoutTokenOrZone guards issue #83: the
// read-only rule inventory must report Wired=false (not attempt a Cloudflare
// API call) when no token/zone is configured, the same precondition as the
// rest of the Cloudflare integration. Uses a bare Server (not newTestServer,
// which sets CF_API_TOKEN/CF_ZONE_ID test env vars) so this stays a pure
// unit test with zero network access.
func TestFetchCFRuleInventory_NotWiredWithoutTokenOrZone(t *testing.T) {
	srv := &Server{cfg: &config.Config{}}
	inv := srv.fetchCFRuleInventory(context.Background(), 3)
	if inv.Wired {
		t.Error("expected Wired=false when no Cloudflare token/zone is configured")
	}
}

// TestCFRuleInventorySnapshot_Caches guards issue #83's read-only call
// budget: repeated calls within cfRuleInventoryCacheTTL must reuse the
// cached snapshot rather than issuing a new (would-be) Cloudflare API call
// each time. Uses a bare unwired Server so the first fetch is a fast,
// network-free "not wired" result, isolating the caching behavior under test.
func TestCFRuleInventorySnapshot_Caches(t *testing.T) {
	srv := &Server{cfg: &config.Config{}}
	first := srv.cfRuleInventorySnapshot(context.Background(), 5)
	srv.cfInventoryMu.Lock()
	srv.cfInventoryCache.TrackedCount = 99 // mutate the cache directly to prove the second call reads it back
	srv.cfInventoryMu.Unlock()

	second := srv.cfRuleInventorySnapshot(context.Background(), 5)
	if second.TrackedCount != 99 {
		t.Errorf("expected cached snapshot (TrackedCount=99) to be reused, got %d", second.TrackedCount)
	}
	_ = first
}

// TestRenderCFRuleInventory_NotWired guards the "no token/zone" render path.
func TestRenderCFRuleInventory_NotWired(t *testing.T) {
	w := &strings.Builder{}
	if err := renderCFRuleInventory(w, cfRuleInventory{Wired: false}); err != nil {
		t.Fatalf("render error: %v", err)
	}
	if !strings.Contains(w.String(), "Not available") {
		t.Errorf("expected not-available message, got %q", w.String())
	}
}

// TestRenderCFRuleInventory_Error guards the live-API-error render path —
// must surface the error, never silently hide the inventory gap.
func TestRenderCFRuleInventory_Error(t *testing.T) {
	w := &strings.Builder{}
	if err := renderCFRuleInventory(w, cfRuleInventory{Wired: true, Error: "rate limited"}); err != nil {
		t.Fatalf("render error: %v", err)
	}
	if !strings.Contains(w.String(), "rate limited") {
		t.Errorf("expected error surfaced in body, got %q", w.String())
	}
}

// TestRenderCFRuleInventory_Counts guards issue #83's core requirement: the
// live/tracked/untracked counts must render as real numbers, not a fake
// "all tracked" or "unavailable" placeholder.
func TestRenderCFRuleInventory_Counts(t *testing.T) {
	w := &strings.Builder{}
	inv := cfRuleInventory{Wired: true, LiveCount: 131, TrackedCount: 5, UntrackedCount: 126}
	if err := renderCFRuleInventory(w, inv); err != nil {
		t.Fatalf("render error: %v", err)
	}
	body := w.String()
	for _, want := range []string{"131", "5", "126", "Cloudflare Rule Inventory"} {
		if !strings.Contains(body, want) {
			t.Errorf("expected %q in body: %s", want, body)
		}
	}
}

// TestFetchCFRuleInventory_ComputesUntrackedCount guards the core of issue
// #83: when wired, the inventory must compute live-vs-tracked counts from
// whatever the Cloudflare API actually returns, with no fabricated/synthetic
// data. Uses newTestServer (token/zone configured) with cfRuleLister
// overridden to a fake, never making a real network call.
func TestFetchCFRuleInventory_ComputesUntrackedCount(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.cfRuleLister = func(context.Context, string, string) ([]cfmodels.IPAccessRule, error) {
		rules := make([]cfmodels.IPAccessRule, 131)
		return rules, nil
	}

	inv := srv.fetchCFRuleInventory(context.Background(), 5)
	if !inv.Wired {
		t.Fatal("expected Wired=true with token/zone configured")
	}
	if inv.LiveCount != 131 || inv.TrackedCount != 5 || inv.UntrackedCount != 126 {
		t.Errorf("expected live=131 tracked=5 untracked=126, got live=%d tracked=%d untracked=%d",
			inv.LiveCount, inv.TrackedCount, inv.UntrackedCount)
	}
}

// TestFetchCFRuleInventory_SurfacesAPIError guards that a Cloudflare API
// failure is surfaced as a real error, never silently swallowed into a fake
// zero-count state.
func TestFetchCFRuleInventory_SurfacesAPIError(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.cfRuleLister = func(context.Context, string, string) ([]cfmodels.IPAccessRule, error) {
		return nil, errors.New("cloudflare 403")
	}

	inv := srv.fetchCFRuleInventory(context.Background(), 5)
	if inv.Error == "" {
		t.Error("expected the API error to be surfaced")
	}
}

func TestHandleCFSyncPage_HTTPIntegration(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.banLifecycleStore = &fakeBanLifecycleStore{entries: []banlifecycle.Entry{
		{IP: "10.0.0.1", Status: banlifecycle.StatusActive, CreatedAt: time.Now().UTC()},
	}}

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/sync", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "CF Ban Sync") {
		t.Error("expected page title")
	}
	if !strings.Contains(body, "Active managed bans") {
		t.Error("expected live managed-state panel")
	}
}
