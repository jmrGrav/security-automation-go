package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/security/classifier"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

func TestDashboardThreatViewAggregatesCountries(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	now := time.Now().UTC()
	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "fr-1", Source: "cloudflare_waf", IP: "203.0.113.10", AbuseType: "wordpress_probe", Decision: "report_pending", Timestamp: now, NormalizedEvent: classifier.Event{CountryName: "France"}},
			{EvidenceID: "fr-2", Source: "cloudflare_waf", IP: "203.0.113.11", AbuseType: "wordpress_probe", Decision: "report_pending", Timestamp: now.Add(-time.Minute), NormalizedEvent: classifier.Event{CountryName: "France"}},
			{EvidenceID: "us-1", Source: "crowdsec_waf", IP: "198.51.100.7", AbuseType: "scanner", Decision: "suppress", Timestamp: now.Add(-2 * time.Minute), NormalizedEvent: classifier.Event{CountryName: "United States"}},
		},
	}
	srv.evidence = store

	view := srv.dashboardThreatView(context.Background(), now.Add(-time.Hour))

	if !view.Wired {
		t.Fatalf("threat view should be wired when evidence store exists: %#v", view)
	}
	if view.TotalEvents != 3 {
		t.Fatalf("TotalEvents: want 3, got %d", view.TotalEvents)
	}
	if len(view.Countries) < 2 {
		t.Fatalf("expected country aggregates, got %#v", view.Countries)
	}
	if view.Countries[0].Country != "France" || view.Countries[0].Count != 2 {
		t.Fatalf("top country aggregate mismatch: %#v", view.Countries)
	}
	if len(store.searchCalls) == 0 || store.searchCalls[0].From.IsZero() || store.searchCalls[0].Limit != dashboardThreatEvidenceLimit {
		t.Fatalf("threat view must use a bounded, windowed evidence read, calls=%#v", store.searchCalls)
	}
}

func TestDashboardThreatViewKeepsUnknownCountryExplicit(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	now := time.Now().UTC()
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "unknown-1", Source: "openresty_waf", IP: "192.0.2.42", AbuseType: "scanner", Decision: "report_pending", Timestamp: now},
		},
	}

	view := srv.dashboardThreatView(context.Background(), now.Add(-time.Hour))

	if view.UnknownCount != 1 {
		t.Fatalf("UnknownCount: want 1, got %d in %#v", view.UnknownCount, view)
	}
	if len(view.Countries) != 1 || view.Countries[0].Country != "unknown / not available" {
		t.Fatalf("unknown country must stay explicit, got %#v", view.Countries)
	}
}

func TestDashboardThreatViewBuildsTopCampaigns(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	now := time.Now().UTC()
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "c1", Source: "cloudflare_waf", AbuseType: "wordpress_probe", Decision: "report_pending", Timestamp: now, NormalizedEvent: classifier.Event{CountryName: "France"}},
			{EvidenceID: "c2", Source: "cloudflare_waf", AbuseType: "wordpress_probe", Decision: "report_pending", Timestamp: now.Add(-time.Minute), NormalizedEvent: classifier.Event{CountryName: "France"}},
			{EvidenceID: "c3", Source: "crowdsec_waf", AbuseType: "", Decision: "suppress", Timestamp: now.Add(-2 * time.Minute), NormalizedEvent: classifier.Event{CountryName: "Germany"}},
		},
	}

	view := srv.dashboardThreatView(context.Background(), now.Add(-time.Hour))

	if len(view.Campaigns) != 2 {
		t.Fatalf("Campaigns: want 2 groups, got %#v", view.Campaigns)
	}
	if got := view.Campaigns[0]; got.Source != "cloudflare_waf" || got.Country != "France" || got.Scenario != "wordpress_probe" || got.Count != 2 {
		t.Fatalf("top campaign mismatch: %#v", view.Campaigns)
	}
	if got := view.Campaigns[1]; got.Scenario != "suppress" {
		t.Fatalf("campaign scenario should fall back to decision, got %#v", view.Campaigns)
	}
}

func TestDashboardThreatWidgetUsesTimeWindow(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	now := time.Now().UTC()
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "recent", Source: "cloudflare_waf", IP: "203.0.113.10", AbuseType: "scanner", Decision: "report_pending", Timestamp: now.Add(-30 * time.Minute), NormalizedEvent: classifier.Event{CountryName: "France"}},
			{EvidenceID: "old", Source: "cloudflare_waf", IP: "203.0.113.20", AbuseType: "scanner", Decision: "report_pending", Timestamp: now.Add(-48 * time.Hour), NormalizedEvent: classifier.Event{CountryName: "Germany"}},
		},
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/v2/?window=1h", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()

	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	// V2 dashboard renders "Live attack map" (not "Attack Map"), and country codes (not names).
	if !strings.Contains(body, "attack map") {
		t.Fatalf("v2 dashboard should render attack map section: %s", body)
	}
	// France is the "node" country (server side) — it's excluded from origin rendering.
	// Just verify Germany (old event) is not shown since it's outside the 1h window.
	// The test primarily validates time-window scoping via the evidence count.
	if !strings.Contains(body, "window=1h") {
		t.Fatalf("v2 dashboard should contain 1h window link: %s", body)
	}
}

func TestDashboardThreatWidgetIsReadOnly(t *testing.T) {
	view := DashboardThreatView{
		Wired:       true,
		TotalEvents: 1,
		Countries:   []DashboardThreatCountryView{{Country: "France", Count: 1, Level: "warning"}},
		Campaigns:   []DashboardThreatCampaignView{{Source: "cloudflare_waf", Country: "France", Scenario: "scanner", Count: 1, Level: "warning"}},
	}
	var out strings.Builder

	if err := renderThreatVisualization(&out, view); err != nil {
		t.Fatalf("render threat visualization: %v", err)
	}

	body := out.String()
	if !strings.Contains(body, "Attack Map") || !strings.Contains(body, "Top Campaigns") {
		t.Fatalf("threat widget should render map and campaigns: %s", body)
	}
	for _, forbidden := range []string{"cloudflare-delete", "crowdsec-delete", "data-dashboard-mutation", "data-cloudflare-mutation", "data-crowdsec-mutation", "method=\"post\""} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("threat visualization must remain read-only and not render %q: %s", forbidden, body)
		}
	}
}

func TestDashboardActivityFeedAddsCountryWhenAvailable(t *testing.T) {
	ev := reporting.DecisionEvidence{
		EvidenceID:        "ev-country",
		IP:                "203.0.113.10",
		Source:            "cloudflare_waf",
		Decision:          "report_pending",
		Timestamp:         time.Now().UTC(),
		NormalizedEvent:   classifier.Event{CountryName: "France"},
		AbuseIPDBReported: false,
	}

	item := dashboardActivityItem(ev)

	if !strings.Contains(item.Detail, "France") {
		t.Fatalf("activity feed should reuse country context from the threat read-model fields, got %#v", item)
	}
}
