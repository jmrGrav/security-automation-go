package ui

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/services/reporting"
)

type cancelSensitiveEvidenceStore struct {
	total int
}

func (s cancelSensitiveEvidenceStore) Append(context.Context, reporting.DecisionEvidence) error {
	return nil
}
func (s cancelSensitiveEvidenceStore) List(context.Context, int) ([]reporting.DecisionEvidence, error) {
	return nil, nil
}
func (s cancelSensitiveEvidenceStore) Get(context.Context, string) (reporting.DecisionEvidence, bool, error) {
	return reporting.DecisionEvidence{}, false, nil
}
func (s cancelSensitiveEvidenceStore) Search(ctx context.Context, _ reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return make([]reporting.DecisionEvidence, s.total), nil
}
func (s cancelSensitiveEvidenceStore) Count(ctx context.Context, _ reporting.EvidenceSearchOptions) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	return s.total, nil
}

func TestDashboardConsolePageUsesEncryptedSQLiteWording(t *testing.T) {
	view := DashboardConsoleView{
		AIProviders: []AIProviderDashboardView{{
			Name:         "OpenAI",
			Status:       "READY",
			Model:        "gpt-4.1-mini",
			SecretState:  "not configured",
			EnabledState: "disabled",
		}},
	}
	var buf bytes.Buffer
	if err := DashboardConsolePage(view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render dashboard console page: %v", err)
	}
	body := buf.String()
	if !strings.Contains(body, "encrypted SQLite credential store") {
		t.Fatalf("dashboard should mention encrypted SQLite credential store, body=%s", body)
	}
	if !strings.Contains(body, `data-live-shell="dashboard"`) {
		t.Fatalf("dashboard should expose a live shell for partial refreshes, body=%s", body)
	}
	if !strings.Contains(body, `data-live-relative-time`) {
		t.Fatalf("dashboard should expose live relative time metadata, body=%s", body)
	}
	if !strings.Contains(body, `dashboard-hub`) || !strings.Contains(body, `href="/providers"`) {
		t.Fatalf("dashboard should expose operator hub cards, body=%s", body)
	}
	if strings.Contains(body, "file-backed secrets") {
		t.Fatalf("dashboard must not mention file-backed secrets, body=%s", body)
	}
}

func TestDashboardViewIgnoresCanceledRequestContextForEvidenceCount(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = cancelSensitiveEvidenceStore{total: 123}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "AbuseIPDB Reported") {
		t.Fatalf("dashboard missing AbuseIPDB summary: %s", body)
	}
	if !strings.Contains(body, ">123<") {
		t.Fatalf("dashboard should render stable evidence count despite canceled request context: %s", body)
	}
}

func TestDashboardViewPopulatesCommandCenter(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = cancelSensitiveEvidenceStore{total: 7}

	view := srv.dashboardConsoleView(context.Background())

	if view.CommandCenter.Health.Level == "" {
		t.Fatalf("command center health score should be populated")
	}
	if view.CommandCenter.Search.Action == "" {
		t.Fatalf("command center search action should be populated")
	}
	if view.CommandCenter.TimeWindow.Active != "24h" {
		t.Fatalf("default command center window: want 24h, got %q", view.CommandCenter.TimeWindow.Active)
	}
	if len(view.CommandCenter.KPIs) == 0 {
		t.Fatalf("command center KPIs should be populated")
	}
}

func TestDashboardConsolePageRendersSOCCommandCenter(t *testing.T) {
	view := DashboardConsoleView{
		UpdatedAt: "2026-06-24T00:00:00Z",
		CommandCenter: DashboardCommandCenterView{
			Health:     DashboardHealthScoreView{Score: 82, Level: "degraded", Summary: "82% platform health", Reasons: []string{"Cloudflare: zone missing"}},
			Search:     DashboardSearchView{Action: "/search", Placeholder: "IP, evidence id"},
			TimeWindow: dashboardTimeWindow("24h"),
			KPIs:       []DashboardKPIView{{Label: "Health", Value: "82%", Detail: "derived platform score", Href: "/health", Level: "degraded"}},
			Activity:   DashboardActivityFeedView{Items: []DashboardActivityItemView{{Timestamp: "2026-06-24T00:00:00Z", Severity: "warning", Title: "report_pending", Detail: "203.0.113.10", Href: "/evidence/ev1"}}, MoreHref: "/timeline"},
			Freshness:  []DashboardFreshnessView{{Label: "Evidence", Level: "healthy", Detail: "updated 0s ago"}},
		},
	}

	var buf bytes.Buffer
	if err := DashboardConsolePage(view).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render dashboard: %v", err)
	}
	body := buf.String()
	for _, want := range []string{"Security Command Center", "Health Score", "82%", "Universal Search", "Live Activity Feed", "Global time bar", "data-command-palette-trigger"} {
		if !strings.Contains(body, want) {
			t.Fatalf("dashboard missing %q: %s", want, body)
		}
	}
}

func TestDashboardConsolePageDoesNotRenderMutationForms(t *testing.T) {
	var buf bytes.Buffer
	if err := DashboardConsolePage(DashboardConsoleView{}).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render dashboard: %v", err)
	}
	body := buf.String()
	for _, forbidden := range []string{"cloudflare-delete", "crowdsec-delete", "data-dashboard-mutation", "data-cloudflare-mutation", "data-crowdsec-mutation"} {
		if strings.Contains(strings.ToLower(body), strings.ToLower(forbidden)) {
			t.Fatalf("dashboard must remain read-only and not render %q: %s", forbidden, body)
		}
	}
}
