package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/services/reporting"
)

type stubEvidenceStore struct {
	items []reporting.DecisionEvidence
}

func (s *stubEvidenceStore) Append(_ context.Context, ev reporting.DecisionEvidence) error {
	s.items = append(s.items, ev)
	return nil
}

func (s *stubEvidenceStore) List(_ context.Context, limit int) ([]reporting.DecisionEvidence, error) {
	if limit > 0 && limit < len(s.items) {
		return s.items[:limit], nil
	}
	return s.items, nil
}

func (s *stubEvidenceStore) Get(_ context.Context, id string) (reporting.DecisionEvidence, bool, error) {
	for _, ev := range s.items {
		if ev.EvidenceID == id {
			return ev, true, nil
		}
	}
	return reporting.DecisionEvidence{}, false, nil
}

func (s *stubEvidenceStore) Search(_ context.Context, opts reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	var out []reporting.DecisionEvidence
	for _, ev := range s.items {
		if opts.Source != "" && ev.Source != opts.Source {
			continue
		}
		if opts.AbuseIPDBReported && !ev.AbuseIPDBReported {
			continue
		}
		if opts.Suppressed && !ev.Suppressed {
			continue
		}
		if opts.Decision != "" && ev.Decision != opts.Decision {
			continue
		}
		out = append(out, ev)
	}
	if opts.Offset > 0 {
		if opts.Offset >= len(out) {
			return nil, nil
		}
		out = out[opts.Offset:]
	}
	if opts.Limit > 0 && len(out) > opts.Limit {
		out = out[:opts.Limit]
	}
	return out, nil
}

func (s *stubEvidenceStore) Count(_ context.Context, opts reporting.EvidenceSearchOptions) (int, error) {
	results, err := s.Search(context.Background(), reporting.EvidenceSearchOptions{
		Source:            opts.Source,
		Decision:          opts.Decision,
		AbuseIPDBReported: opts.AbuseIPDBReported,
		Suppressed:        opts.Suppressed,
		SuppressionReason: opts.SuppressionReason,
	})
	return len(results), err
}

func TestPipelineHealthMatrix(t *testing.T) {
	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			// cloudflare_waf: 1 reported, 1 suppressed, 1 pending
			{EvidenceID: "c1", Source: "cloudflare_waf", AbuseIPDBReported: true},
			{EvidenceID: "c2", Source: "cloudflare_waf", Suppressed: true},
			{EvidenceID: "c3", Source: "cloudflare_waf", Decision: "report_pending"},
			// crowdsec_waf: 2 reported, 1 pending
			{EvidenceID: "cs1", Source: "crowdsec_waf", AbuseIPDBReported: true},
			{EvidenceID: "cs2", Source: "crowdsec_waf", AbuseIPDBReported: true},
			{EvidenceID: "cs3", Source: "crowdsec_waf", Decision: "report_pending"},
			// openresty_waf: 0 events (no rows)
		},
	}

	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/pipeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()

	for _, want := range []string{
		"Cloudflare WAF", "CrowdSec WAF", "OpenResty WAF",
		"Pipeline Health",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %q in pipeline page", want)
		}
	}
}

func TestPipelineHealthMatrixCounts(t *testing.T) {
	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "c1", Source: "cloudflare_waf", AbuseIPDBReported: true},
			{EvidenceID: "c2", Source: "cloudflare_waf", Suppressed: true},
			{EvidenceID: "c3", Source: "cloudflare_waf", Decision: "report_pending"},
			{EvidenceID: "cs1", Source: "crowdsec_waf", AbuseIPDBReported: true},
			{EvidenceID: "cs2", Source: "crowdsec_waf", AbuseIPDBReported: true},
		},
	}

	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store

	view := srv.buildPipelineHealthView(context.Background())

	if view.Error != "" {
		t.Fatalf("unexpected error: %s", view.Error)
	}

	bySource := make(map[string]PipelineHealthRow, len(view.Rows))
	for _, r := range view.Rows {
		bySource[r.Source] = r
	}

	cf := bySource["Cloudflare WAF"]
	if cf.Classified != 3 {
		t.Errorf("cloudflare classified: want 3, got %d", cf.Classified)
	}
	if cf.Reported != 1 {
		t.Errorf("cloudflare reported: want 1, got %d", cf.Reported)
	}
	if cf.Suppressed != 1 {
		t.Errorf("cloudflare suppressed: want 1, got %d", cf.Suppressed)
	}
	if cf.Pending != 1 {
		t.Errorf("cloudflare pending: want 1, got %d", cf.Pending)
	}

	cs := bySource["CrowdSec WAF"]
	if cs.Classified != 2 {
		t.Errorf("crowdsec classified: want 2, got %d", cs.Classified)
	}
	if cs.Reported != 2 {
		t.Errorf("crowdsec reported: want 2, got %d", cs.Reported)
	}

	or := bySource["OpenResty WAF"]
	if or.Classified != 0 {
		t.Errorf("openresty classified: want 0, got %d", or.Classified)
	}

	if view.Total.Classified != 5 {
		t.Errorf("total classified: want 5, got %d", view.Total.Classified)
	}
	if view.Total.Reported != 3 {
		t.Errorf("total reported: want 3, got %d", view.Total.Reported)
	}
}

func TestPipelineHealthMatrixNoEvidence(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	// srv.evidence is nil — daemon not started

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/pipeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "daemon not yet started") {
		t.Errorf("expected 'daemon not yet started' in empty-state body: %s", rr.Body.String())
	}
}
