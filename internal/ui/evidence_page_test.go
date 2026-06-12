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

// fakeEvidenceStore is a minimal in-memory evidence store for UI tests.
type fakeEvidenceStore struct {
	records []reporting.DecisionEvidence
}

func (f *fakeEvidenceStore) Append(_ context.Context, ev reporting.DecisionEvidence) error {
	f.records = append(f.records, ev)
	return nil
}

func (f *fakeEvidenceStore) List(_ context.Context, limit int) ([]reporting.DecisionEvidence, error) {
	if limit <= 0 || limit > len(f.records) {
		return f.records, nil
	}
	return f.records[:limit], nil
}

func (f *fakeEvidenceStore) Get(_ context.Context, id string) (reporting.DecisionEvidence, bool, error) {
	for _, r := range f.records {
		if r.EvidenceID == id {
			return r, true, nil
		}
	}
	return reporting.DecisionEvidence{}, false, nil
}

func (f *fakeEvidenceStore) Search(_ context.Context, opts reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	out := make([]reporting.DecisionEvidence, 0, len(f.records))
	for _, r := range f.records {
		if opts.IP != "" && r.IP != opts.IP {
			continue
		}
		if opts.SuppressionReason != "" && r.SuppressionReason != opts.SuppressionReason {
			continue
		}
		if opts.AbuseIPDBReported && !r.AbuseIPDBReported {
			continue
		}
		if opts.Suppressed && !r.Suppressed {
			continue
		}
		out = append(out, r)
	}
	limit := opts.Limit
	if limit <= 0 {
		limit = len(out)
	}
	if opts.Offset >= len(out) {
		return nil, nil
	}
	end := opts.Offset + limit
	if end > len(out) {
		end = len(out)
	}
	return out[opts.Offset:end], nil
}

func (f *fakeEvidenceStore) Count(_ context.Context, opts reporting.EvidenceSearchOptions) (int, error) {
	all, err := f.Search(context.Background(), reporting.EvidenceSearchOptions{
		IP:                opts.IP,
		Source:            opts.Source,
		Decision:          opts.Decision,
		SuppressionReason: opts.SuppressionReason,
		AbuseIPDBReported: opts.AbuseIPDBReported,
		Suppressed:        opts.Suppressed,
	})
	return len(all), err
}

func TestEvidencePage_RequiresAuth(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	req := httptest.NewRequest(http.MethodGet, "/evidence", nil)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected redirect to login, got %d", rr.Code)
	}
}

func TestEvidencePage_NoStoreShowsEmptyState(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/evidence", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "daemon not yet started") {
		t.Fatalf("expected daemon-not-started message, got: %s", rr.Body.String())
	}
}

func TestEvidencePage_ShowsAllEvents(t *testing.T) {
	store := &fakeEvidenceStore{
		records: []reporting.DecisionEvidence{
			{EvidenceID: "ev1", IP: "1.2.3.4", Source: "cloudflare_waf", AbuseType: "scanner", RiskScore: 10, Confidence: 0.82, Decision: "local_block", Timestamp: time.Now()},
			{EvidenceID: "ev2", IP: "5.6.7.8", Source: "crowdsec_waf", AbuseType: "exploit_attempt", RiskScore: 20, Confidence: 0.95, Decision: "report_pending", Timestamp: time.Now()},
			{EvidenceID: "ev3", IP: "9.10.11.12", Source: "cloudflare_waf", AbuseType: "wordpress_probe", RiskScore: 5, Confidence: 0.65, Decision: "suppress", Suppressed: true, SuppressionReason: "low_confidence", Timestamp: time.Now()},
		},
	}
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/evidence", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "1.2.3.4") {
		t.Errorf("expected IP 1.2.3.4 in evidence page, got: %s", body)
	}
	if !strings.Contains(body, "5.6.7.8") {
		t.Errorf("expected IP 5.6.7.8 in evidence page")
	}
	if !strings.Contains(body, "scanner") {
		t.Errorf("expected abuse_type=scanner in evidence page")
	}
}

func TestEvidencePage_ReportedFilter(t *testing.T) {
	store := &fakeEvidenceStore{
		records: []reporting.DecisionEvidence{
			{EvidenceID: "ev1", IP: "1.2.3.4", AbuseType: "scanner", AbuseIPDBReported: true, Timestamp: time.Now()},
			{EvidenceID: "ev2", IP: "5.6.7.8", AbuseType: "wordpress_probe", AbuseIPDBReported: false, Timestamp: time.Now()},
		},
	}
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/evidence?filter=reported", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "1.2.3.4") {
		t.Errorf("expected reported IP 1.2.3.4 to appear in filtered view")
	}
	if strings.Contains(body, "5.6.7.8") {
		t.Errorf("non-reported IP 5.6.7.8 must not appear in reported filter")
	}
}

func TestEvidencePage_IPColumnLinksToForensic(t *testing.T) {
	store := &fakeEvidenceStore{
		records: []reporting.DecisionEvidence{
			{EvidenceID: "ev1", IP: "1.2.3.4", Source: "cloudflare_waf", AbuseType: "scanner", Decision: "local_block", Timestamp: time.Now()},
		},
	}
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/evidence", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, `/forensic?ip=1.2.3.4`) {
		t.Errorf("expected forensic deep-link for IP in evidence table, body: %s", body)
	}
}

func TestForensicPage_ShowsLocalEvidenceForIP(t *testing.T) {
	store := &fakeEvidenceStore{
		records: []reporting.DecisionEvidence{
			{EvidenceID: "ev1", IP: "203.0.113.5", Source: "cloudflare_waf", AbuseType: "scanner", RiskScore: 10, Decision: "local_block", Timestamp: time.Now()},
			{EvidenceID: "ev2", IP: "10.0.0.1", Source: "cloudflare_waf", AbuseType: "wordpress_probe", RiskScore: 5, Decision: "observe_only", Timestamp: time.Now()},
		},
	}
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/forensic", strings.NewReader("ip=203.0.113.5"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Local Evidence History") {
		t.Errorf("expected local evidence section, got: %s", body)
	}
	if !strings.Contains(body, "scanner") {
		t.Errorf("expected evidence type in forensic page")
	}
	// IP 10.0.0.1 must not appear — only 203.0.113.5 records shown
	if strings.Contains(body, "10.0.0.1") {
		t.Errorf("evidence for other IPs must not appear in forensic lookup for 203.0.113.5")
	}
}
