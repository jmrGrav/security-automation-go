package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/services/reporting"
)

func TestCommandCenterViewDefaultsAreSafe(t *testing.T) {
	view := DashboardCommandCenterView{}

	if view.Health.Score != 0 {
		t.Fatalf("zero-value health score must be 0, got %d", view.Health.Score)
	}
	if view.Health.Level != "" {
		t.Fatalf("zero-value health level should be empty until derived, got %q", view.Health.Level)
	}
	if len(view.Activity.Items) != 0 {
		t.Fatalf("zero-value activity feed should be empty")
	}
	if view.Search.Action != "" {
		t.Fatalf("zero-value search action should be empty until rendered")
	}
}

func TestDashboardHealthScoreDerivesHealthyState(t *testing.T) {
	score := dashboardHealthScore([]StatusItem{
		{Label: "Runtime", Level: "healthy", Detail: "UI mode active"},
		{Label: "Cloudflare", Level: "live", Detail: "mutations live"},
	}, EnvironmentWidget{Healthy: 2, Total: 2, Green: 2}, nil, nil, nil, true)

	if score.Score != 100 {
		t.Fatalf("Score: want 100, got %d", score.Score)
	}
	if score.Level != "healthy" {
		t.Fatalf("Level: want healthy, got %q", score.Level)
	}
	if len(score.Reasons) == 0 {
		t.Fatalf("expected health score reasons")
	}
}

func TestDashboardHealthScoreSurfacesDegradedReasons(t *testing.T) {
	score := dashboardHealthScore([]StatusItem{
		{Label: "Runtime", Level: "healthy", Detail: "UI mode active"},
		{Label: "Cloudflare", Level: "warning", Detail: "zone missing"},
		{Label: "HA / fencing", Level: "unavailable", Detail: "no HA subsystem configured"},
	}, EnvironmentWidget{Healthy: 1, Total: 3, Green: 1, Yellow: 1, Red: 1}, nil, nil, nil, false)

	if score.Score >= 100 {
		t.Fatalf("degraded inputs must reduce score, got %d", score.Score)
	}
	if score.Level == "healthy" {
		t.Fatalf("degraded inputs must not report healthy")
	}
	for _, want := range []string{"Cloudflare: zone missing", "HA / fencing: no HA subsystem configured", "Evidence store: unavailable"} {
		if !stringSliceContains(score.Reasons, want) {
			t.Fatalf("missing reason %q in %#v", want, score.Reasons)
		}
	}
}

func stringSliceContains(items []string, want string) bool {
	for _, item := range items {
		if item == want {
			return true
		}
	}
	return false
}

func TestDashboardSearchRoutesIPToForensic(t *testing.T) {
	got := dashboardSearchTarget("203.0.113.10")
	if got != "/v2/investigate?ip=203.0.113.10" {
		t.Fatalf("IP search target: want v2 investigate route, got %q", got)
	}
}

func TestDashboardSearchRoutesEvidenceIDToEvidenceDetail(t *testing.T) {
	got := dashboardSearchTarget("ev-abc123")
	if got != "/evidence/ev-abc123" {
		t.Fatalf("evidence search target: want evidence detail, got %q", got)
	}
}

func TestDashboardSearchRoutesProviderKeywordToProviders(t *testing.T) {
	got := dashboardSearchTarget("cloudflare")
	if got != "/v2/providers?q=cloudflare" {
		t.Fatalf("provider search target: want v2 providers route, got %q", got)
	}
}

func TestDashboardSearchRoutesGeneralKeywordToTimeline(t *testing.T) {
	got := dashboardSearchTarget("wordpress probe")
	if got != "/v2/timeline?q=wordpress+probe" {
		t.Fatalf("general search target: want v2 timeline route, got %q", got)
	}
}

func TestDashboardTimeWindowDefaultsTo24h(t *testing.T) {
	window := dashboardTimeWindow("")
	if window.Active != "24h" {
		t.Fatalf("Active: want 24h, got %q", window.Active)
	}
	if len(window.Options) != 4 {
		t.Fatalf("expected 4 time window options, got %d", len(window.Options))
	}
}

func TestDashboardTimeWindowAcceptsAllowedValuesOnly(t *testing.T) {
	if got := dashboardTimeWindow("7d").Active; got != "7d" {
		t.Fatalf("Active: want 7d, got %q", got)
	}
	if got := dashboardTimeWindow("forever").Active; got != "24h" {
		t.Fatalf("invalid window should default to 24h, got %q", got)
	}
}

func TestDashboardTimeWindowFiltersEvidenceMetrics(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	now := time.Now().UTC()
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "recent", Source: "cloudflare_waf", AbuseIPDBReported: true, Timestamp: now.Add(-30 * time.Minute)},
			{EvidenceID: "old", Source: "cloudflare_waf", AbuseIPDBReported: true, Timestamp: now.Add(-48 * time.Hour)},
		},
	}

	// Test via the view model directly — the windowed KPI scoping is in
	// dashboardConsoleViewForWindow, not in the rendering layer.
	view1h := srv.dashboardConsoleViewForWindow(context.Background(), "1h")
	view24h := srv.dashboardConsoleViewForWindow(context.Background(), "24h")

	var kpi1h, kpi24h DashboardKPIView
	for _, kpi := range view1h.CommandCenter.KPIs {
		if kpi.Label == "AbuseIPDB reports" {
			kpi1h = kpi
		}
	}
	for _, kpi := range view24h.CommandCenter.KPIs {
		if kpi.Label == "AbuseIPDB reports" {
			kpi24h = kpi
		}
	}

	if kpi1h.Value != "1" {
		t.Fatalf("1h window: expected 1 windowed report, got %q", kpi1h.Value)
	}
	// old is -48h, outside the 24h window; only recent (-30min) is in scope.
	if kpi24h.Value != "1" {
		t.Fatalf("24h window: expected 1 windowed report (old is -48h, outside window), got %q", kpi24h.Value)
	}
}

func TestDashboardProvidersKPIIncludesUnifiedProviders(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	view := srv.dashboardConsoleView(context.Background())

	for _, kpi := range view.CommandCenter.KPIs {
		if kpi.Label != "Providers" {
			continue
		}
		if kpi.Value != "9" {
			t.Fatalf("Providers KPI must include AI and non-AI providers, got %#v", kpi)
		}
		return
	}
	t.Fatal("Providers KPI not found")
}

func TestDashboardFreshnessMarksUnavailable(t *testing.T) {
	got := dashboardFreshness("Evidence", false, time.Time{})
	if got.Level != "unavailable" || got.Detail == "" {
		t.Fatalf("expected unavailable freshness with detail, got %#v", got)
	}
}

func TestDashboardFreshnessUsesLatestEvidenceTimestamp(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "old", Source: "cloudflare_waf", Timestamp: time.Now().Add(-10 * time.Minute).UTC()},
		},
	}

	view := srv.dashboardConsoleView(context.Background())

	for _, item := range view.CommandCenter.Freshness {
		if item.Label != "Evidence" {
			continue
		}
		if item.Level != "warning" || !strings.Contains(item.Detail, "stale") {
			t.Fatalf("Evidence freshness must reflect latest evidence timestamp, got %#v", item)
		}
		return
	}
	t.Fatal("Evidence freshness row not found")
}

func TestDashboardActivityFeedUsesBoundedEvidenceRead(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "ev1", IP: "203.0.113.10", Source: "cloudflare_waf", Decision: "report_pending", Timestamp: time.Now().UTC()},
			{EvidenceID: "ev2", IP: "203.0.113.11", Source: "crowdsec_waf", Decision: "suppress", Timestamp: time.Now().UTC()},
		},
	}
	srv.evidence = store

	feed := srv.dashboardActivityFeed(context.Background())

	if feed.Limit != dashboardActivityLimit {
		t.Fatalf("Limit: want %d, got %d", dashboardActivityLimit, feed.Limit)
	}
	if len(store.searchCalls) == 0 {
		t.Fatalf("expected bounded evidence Search call")
	}
	if store.searchCalls[0].Limit != dashboardActivityLimit {
		t.Fatalf("evidence Search limit: want %d, got %d", dashboardActivityLimit, store.searchCalls[0].Limit)
	}
	if len(feed.Items) != 2 {
		t.Fatalf("feed items: want 2, got %d", len(feed.Items))
	}
}

func TestDashboardActivityFeedUnavailableWhenEvidenceMissing(t *testing.T) {
	srv := newCFTestServer(t, nil, "tok", "zone")
	feed := srv.dashboardActivityFeed(context.Background())

	if feed.EmptyText == "" {
		t.Fatalf("missing evidence store should render a degraded empty state")
	}
	if len(feed.Items) != 0 {
		t.Fatalf("missing evidence store should not fake feed items")
	}
}

func TestDashboardSearchEndpointRedirectsToForensicForIP(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/search?q=203.0.113.10", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "/v2/investigate?ip=203.0.113.10" {
		t.Fatalf("Location: got %q", got)
	}
}

func TestDashboardSearchEndpointRedirectsBlankToTimeline(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/search", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected 303 redirect, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("Location"); got != "/v2/timeline" {
		t.Fatalf("Location: got %q", got)
	}
}
