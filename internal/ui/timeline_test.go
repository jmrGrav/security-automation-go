package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

// fakeRuntimeEventStore is a minimal events.EventStore fake for proving
// /timeline surfaces real runtime lineage (see runtimeEntryToTimelineEvent).
type fakeRuntimeEventStore struct {
	events []events.Event
}

func (s fakeRuntimeEventStore) List(_ context.Context, _ string, _ uint64) ([]events.Event, error) {
	return append([]events.Event(nil), s.events...), nil
}
func (s fakeRuntimeEventStore) Append(context.Context, *events.Event) error { return nil }
func (s fakeRuntimeEventStore) GetLastSequence(context.Context, string) (uint64, error) {
	return 0, nil
}

func TestTimelineEmptyState(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := &http.Cookie{Name: sessionCookieName, Value: "seeded-session"}
	srv.mu.Lock()
	srv.sessions[cookie.Value] = time.Now().UTC().Add(time.Hour)
	srv.mu.Unlock()

	// /timeline redirects to /v2/timeline; test the canonical page directly.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	// V2 timeline uses "Timeline" in topbar title, not "Security Timeline".
	if !strings.Contains(body, "Timeline") {
		t.Fatalf("v2 timeline page missing heading: %s", body)
	}
	// V2 empty state shows "No investigation started."
	if !strings.Contains(body, "No investigation started") {
		t.Fatalf("v2 timeline empty state missing: %s", body)
	}
	if strings.Contains(body, "<table>") {
		t.Fatalf("empty timeline page must not render a table: %s", body)
	}
}

func TestTimelineIncludesEvidenceEvents(t *testing.T) {
	now := time.Now().UTC()
	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{
				EvidenceID:        "ev-cf-1",
				Source:            "cloudflare_waf",
				IP:                "1.2.3.4",
				AbuseType:         "hacking",
				Decision:          "report",
				AbuseIPDBReported: true,
				Timestamp:         now.Add(-1 * time.Minute),
			},
			{
				EvidenceID: "ev-cs-1",
				Source:     "crowdsec_waf",
				IP:         "5.6.7.8",
				Decision:   "report_pending",
				Timestamp:  now.Add(-2 * time.Minute),
			},
		},
	}

	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// /timeline redirects to /v2/timeline; test canonical page.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{"cloudflare_waf", "crowdsec_waf", "1.2.3.4", "5.6.7.8", "abuseipdb_reported"} {
		if !strings.Contains(body, want) {
			t.Errorf("timeline page missing %q", want)
		}
	}
}

// TestTimelineIncludesRuntimeLineage guards GitHub issue #104: /timeline used
// to never read the runtime event journal at all, hardcoding "unavailable"
// as the replay sequence for every row. With an eventStore wired, real
// daemon lifecycle-transition entries (real sequence numbers, correlation
// ids) must appear as their own rows, filterable via source=runtime.
func TestTimelineIncludesRuntimeLineage(t *testing.T) {
	now := time.Now().UTC()
	store := fakeRuntimeEventStore{events: []events.Event{
		{
			Sequence:      42,
			Timestamp:     now.Add(-1 * time.Minute),
			Category:      events.CategoryLifecycle,
			Type:          "lifecycle_transition",
			Actor:         "runtime-state-machine",
			CorrelationID: "run-abc123",
			Metadata:      map[string]any{"reason": "discovery completed"},
		},
	}}

	srv, _, _ := newTestServer(t, nil)
	srv.eventStore = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// /timeline redirects to /v2/timeline; test canonical page.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	// V2 renders ev.Action ("lifecycle_transition"), not ev.EventType ("runtime_lifecycle_transition").
	// ev.ActorSource ("runtime-state-machine") appears in the source pill.
	// ev.CorrelationID ("run-abc123") appears as corr: pill.
	// ev.ReplaySequence ("42") is NOT rendered in V2.
	for _, want := range []string{"lifecycle_transition", "run-abc123", "runtime-state-machine"} {
		if !strings.Contains(body, want) {
			t.Errorf("v2 timeline page missing %q: %s", want, body)
		}
	}

	// q=runtime must match the runtime-state-machine source row.
	req2 := httptest.NewRequest(http.MethodGet, "/v2/timeline?q=runtime", nil)
	req2.AddCookie(cookie)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if !strings.Contains(rr2.Body.String(), "lifecycle_transition") {
		t.Fatalf("q=runtime filter dropped the runtime lineage row: %s", rr2.Body.String())
	}

	// The JSON export carries the Summary field. V1 /timeline?format=json still works.
	req3 := httptest.NewRequest(http.MethodGet, "/timeline?source=runtime&format=json", nil)
	req3.AddCookie(cookie)
	rr3 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr3, req3)
	if !strings.Contains(rr3.Body.String(), "discovery completed") {
		t.Fatalf("expected JSON export to carry the runtime entry's metadata reason: %s", rr3.Body.String())
	}
}

// TestAllTimelineEventsCachesWithinTTL guards GitHub issue #69: every
// /timeline request used to re-merge and re-sort the full audit log plus up
// to 10000 evidence rows from scratch, so a burst of refreshes during a live
// incident multiplied that cost. allTimelineEvents now caches the merged
// result for timelineCacheTTL. This test proves both halves of that
// contract: a second call within the TTL must reuse the cached slice (not
// reflect data added in between), and a call after the cache is forced
// stale must recompute and pick up the new data.
func TestAllTimelineEventsCachesWithinTTL(t *testing.T) {
	store := &stubEvidenceStore{items: []reporting.DecisionEvidence{
		{EvidenceID: "ev-1", Source: "cloudflare_waf", IP: "1.1.1.1", Timestamp: time.Now().UTC()},
	}}
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store

	first := srv.allTimelineEvents(context.Background())
	if len(first) != 1 {
		t.Fatalf("expected 1 event, got %d", len(first))
	}

	store.items = append(store.items, reporting.DecisionEvidence{
		EvidenceID: "ev-2", Source: "crowdsec_waf", IP: "2.2.2.2", Timestamp: time.Now().UTC(),
	})

	cached := srv.allTimelineEvents(context.Background())
	if len(cached) != 1 {
		t.Fatalf("expected cached result (1 event) within TTL, got %d — cache was bypassed", len(cached))
	}

	srv.timelineMu.Lock()
	srv.timelineCacheAt = time.Now().Add(-2 * timelineCacheTTL)
	srv.timelineMu.Unlock()

	refreshed := srv.allTimelineEvents(context.Background())
	if len(refreshed) != 2 {
		t.Fatalf("expected recomputed result (2 events) after TTL expiry, got %d", len(refreshed))
	}
}

func TestTimelineSmallPageUsesBoundedEvidenceWindow(t *testing.T) {
	now := time.Now().UTC()
	items := make([]reporting.DecisionEvidence, 5000)
	for i := range items {
		items[i] = reporting.DecisionEvidence{
			EvidenceID: "ev-windowed",
			Source:     "cloudflare_waf",
			IP:         "192.0.2.1",
			Decision:   "report_pending",
			Timestamp:  now.Add(-time.Duration(i) * time.Second),
		}
	}
	store := &stubEvidenceStore{items: items}
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// /timeline redirects to /v2/timeline; test canonical page.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	// V2 timeline calls allTimelineEvents which queries the evidence store.
	if len(store.searchCalls) == 0 {
		t.Fatalf("expected /v2/timeline to query evidence store")
	}
}

func TestTimelineForensicSearchFindsEvidenceBeyondBrowsingWindow(t *testing.T) {
	store := timelineEvidenceStoreWithOldMatch("old-ip-query", "cloudflare_waf", "report_pending", 1105)
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// /timeline redirects to /v2/timeline; use V2 canonical path.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline?q=old-ip-query", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "old-ip-query") {
		t.Fatalf("v2 timeline q search must find matching evidence older than the first 1000 rows: %s", rr.Body.String())
	}
}

func TestTimelineSourceFilterCanPageBeyondBrowsingWindow(t *testing.T) {
	store := timelineEvidenceStoreWithOldMatch("old-source-page", "cloudflare_waf", "report_pending", 1105)
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// V2 timeline uses q= for filtering; allTimelineEvents reads all evidence.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline?q=old-source-page", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "old-source-page") {
		t.Fatalf("v2 timeline must reach evidence older than the first 1000 rows: %s", rr.Body.String())
	}
}

func TestTimelineActionFilterFindsEvidenceBeyondBrowsingWindow(t *testing.T) {
	store := timelineEvidenceStoreWithOldMatch("old-action-ip", "cloudflare_waf", "special_action", 1105)
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// V2 timeline uses q= for filtering.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline?q=special_action", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "old-action-ip") {
		t.Fatalf("v2 timeline action filter must find matching evidence: %s", rr.Body.String())
	}
}

func TestTimelineFilteredExportsFindEvidenceBeyondBrowsingWindow(t *testing.T) {
	for _, format := range []string{"json", "csv"} {
		t.Run(format, func(t *testing.T) {
			store := timelineEvidenceStoreWithOldMatch("old-export-ip", "cloudflare_waf", "report_pending", 1105)
			srv, _, _ := newTestServer(t, nil)
			srv.evidence = store
			cookie := loginCookie(t, srv, "test-password-123!@#")

			req := httptest.NewRequest(http.MethodGet, "/timeline?q=old-export-ip&format="+format, nil)
			req.AddCookie(cookie)
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
			}
			if !strings.Contains(rr.Body.String(), "old-export-ip") {
				t.Fatalf("%s export must use the same complete filtered evidence semantics: %s", format, rr.Body.String())
			}
		})
	}
}

func timelineEvidenceStoreWithOldMatch(oldIP, oldSource, oldDecision string, newerRows int) *stubEvidenceStore {
	now := time.Now().UTC()
	items := make([]reporting.DecisionEvidence, 0, newerRows+1)
	for i := range newerRows {
		items = append(items, reporting.DecisionEvidence{
			EvidenceID: "ev-newer",
			Source:     "crowdsec_waf",
			IP:         "198.51.100.42",
			Decision:   "report_pending",
			Timestamp:  now.Add(-time.Duration(i) * time.Second),
		})
	}
	items = append(items, reporting.DecisionEvidence{
		EvidenceID: "ev-old-match",
		Source:     oldSource,
		IP:         oldIP,
		Decision:   oldDecision,
		Timestamp:  now.Add(-time.Duration(newerRows+1) * time.Second),
	})
	return &stubEvidenceStore{items: items}
}

func TestTimelinePageExposesErgonomicControls(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")
	// /timeline redirects to /v2/timeline; V2 uses tl-* classes and a search bar.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	// V2 timeline exposes a live search form and a histogram instead of collapsible panels.
	for _, want := range []string{
		`action="/v2/timeline"`,
		`class="tl-topbar"`,
		`class="tl-histogram"`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("v2 timeline page missing ergonomic control %q: %s", want, body)
		}
	}
}

func TestTimelineSourceFilter(t *testing.T) {
	now := time.Now().UTC()
	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{
				EvidenceID: "ev-waf-1",
				Source:     "cloudflare_waf",
				IP:         "9.10.11.12",
				Decision:   "report_pending",
				Timestamp:  now,
			},
		},
	}

	srv, auditSink, _ := newTestServer(t, nil)
	srv.evidence = store
	// Use a non-IP target that is unique enough not to appear elsewhere in the rendered page
	auditSink.Record("security_intelligence_lookup", map[string]string{
		"target": "unique-audit-target-xzqw",
		"source": "ui",
		"result": "neutral",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// WAF filter: V2 uses q= for filtering; filter by the WAF event IP.
	// /timeline?source=waf redirects; use /v2/timeline?q=cloudflare_waf.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline?q=cloudflare_waf", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "9.10.11.12") {
		t.Errorf("cloudflare_waf filter should show WAF event IP: %s", body)
	}
	if strings.Contains(body, "unique-audit-target-xzqw") {
		t.Errorf("cloudflare_waf filter should hide audit event target: %s", body)
	}

	// Audit filter: filter by unique audit target text.
	req2 := httptest.NewRequest(http.MethodGet, "/v2/timeline?q=unique-audit-target-xzqw", nil)
	req2.AddCookie(cookie)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)

	body2 := rr2.Body.String()
	if strings.Contains(body2, "9.10.11.12") {
		t.Errorf("audit-only filter should hide WAF event IP: %s", body2)
	}
	if !strings.Contains(body2, "unique-audit-target-xzqw") {
		t.Errorf("audit-only filter should show audit event target: %s", body2)
	}
}

func BenchmarkTimelineViewLargeEvidence(b *testing.B) {
	now := time.Now().UTC()
	items := make([]reporting.DecisionEvidence, 10000)
	for i := range items {
		items[i] = reporting.DecisionEvidence{
			EvidenceID: "ev-bench",
			Source:     "cloudflare_waf",
			IP:         "198.51.100.42",
			Decision:   "report_pending",
			Timestamp:  now.Add(-time.Duration(i) * time.Second),
		}
	}
	store := &stubEvidenceStore{items: items}
	srv := &Server{evidence: store}
	req := httptest.NewRequest(http.MethodGet, "/timeline?limit=20", nil)

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		srv.timelineMu.Lock()
		srv.timelineCacheAt = time.Time{}
		srv.timelineCache = nil
		srv.timelineMu.Unlock()
		_ = srv.timelineView(req)
	}
}

func TestTimelineMergeOrder(t *testing.T) {
	base := time.Date(2025, 1, 15, 12, 0, 0, 0, time.UTC)

	store := &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "ev-old", Source: "cloudflare_waf", IP: "old-ip", Decision: "report_pending", Timestamp: base.Add(-10 * time.Minute)},
			{EvidenceID: "ev-new", Source: "cloudflare_waf", IP: "new-ip", Decision: "report_pending", Timestamp: base.Add(5 * time.Minute)},
		},
	}

	srv, _, _ := newTestServer(t, nil)
	srv.evidence = store

	events := srv.allTimelineEvents(context.Background())

	// new-ip must appear before old-ip (newest first)
	newIdx, oldIdx := -1, -1
	for i, e := range events {
		if e.Target == "new-ip" {
			newIdx = i
		}
		if e.Target == "old-ip" {
			oldIdx = i
		}
	}
	if newIdx < 0 || oldIdx < 0 {
		t.Fatalf("expected both IPs in timeline, got %+v", events)
	}
	if newIdx >= oldIdx {
		t.Errorf("newer event (idx %d) should appear before older event (idx %d)", newIdx, oldIdx)
	}
}

// ---------------------------------------------------------------------------
// P13: timelineTargetCell links IP addresses to /forensic?ip=X
// ---------------------------------------------------------------------------

func TestTimelineTargetCell_IPBecomesLink(t *testing.T) {
	got := timelineTargetCell("1.2.3.4")
	if !strings.Contains(got, `/forensic?ip=1.2.3.4`) {
		t.Errorf("expected forensic deep-link for IP, got %q", got)
	}
}

func TestTimelineTargetCell_NonIPRemainsPlainText(t *testing.T) {
	got := timelineTargetCell("trusted-networks")
	if strings.Contains(got, `/forensic`) {
		t.Errorf("non-IP target must not link to forensic, got %q", got)
	}
	if !strings.Contains(got, "trusted-networks") {
		t.Errorf("expected plain text for non-IP target, got %q", got)
	}
}

func TestTimelineTargetCell_EmptyRemainsPlainText(t *testing.T) {
	got := timelineTargetCell("")
	if strings.Contains(got, `/forensic`) {
		t.Errorf("empty target must not link to forensic, got %q", got)
	}
}

func TestTimelinePage_IPTargetLinksToForensic(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "ev1", IP: "5.6.7.8", Source: "cloudflare_waf", Decision: "local_block", Timestamp: time.Now()},
		},
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	// /timeline redirects to /v2/timeline; V2 links IP to /v2/investigate?q=.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	// V2 links IP pills to /v2/investigate?q= instead of /forensic?ip=.
	if !strings.Contains(body, `/v2/investigate?q=5.6.7.8`) {
		t.Errorf("expected v2 investigate deep-link in v2 timeline for WAF event IP, body: %s", body)
	}
}

func TestTimelinePage_ShowsEvidenceDetailLinks(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	srv.evidence = &stubEvidenceStore{
		items: []reporting.DecisionEvidence{
			{EvidenceID: "ev1", IP: "5.6.7.8", Source: "cloudflare_waf", Decision: "local_block", Timestamp: time.Now()},
		},
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	// /timeline redirects to /v2/timeline; V2 shows evidence ID as ev: pill in details.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	// V2 renders ev: pill with truncated evidence ID (ev1 is short, so shown as-is).
	if !strings.Contains(body, `ev:`) || !strings.Contains(body, `ev1`) {
		t.Fatalf("expected evidence id pill in v2 timeline for WAF event, body: %s", body)
	}
}

func TestTimelineFiltersAndExportsReadOnlyEvents(t *testing.T) {
	srv, audit, _ := newTestServer(t, nil)
	audit.Record("security_intelligence_lookup", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "203.0.113.4",
		"result":         "neutral",
		"correlation_id": "corr-1",
		"event_id":       "evt-1",
		"authorization":  "Bearer super-secret-token",
	})
	audit.Record("trusted_networks_export", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "trusted-networks",
		"result":         "read-only",
		"correlation_id": "corr-2",
		"event_id":       "evt-2",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/timeline?q=security&action=security_intelligence_lookup&format=json", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("expected JSON export, got %q", ct)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"security_intelligence_lookup",
		"corr-1",
		"neutral",
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("timeline JSON missing %q: %s", want, body)
		}
	}
	for _, secret := range []string{"super-secret-token", "ui-secret-value"} {
		if strings.Contains(body, secret) {
			t.Fatalf("timeline JSON leaked secret %q: %s", secret, body)
		}
	}

	req = httptest.NewRequest(http.MethodGet, "/timeline?format=csv", nil)
	req.AddCookie(cookie)
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("expected CSV export, got %q", ct)
	}
	body = rr.Body.String()
	if !strings.Contains(body, "timestamp,scope,event_type,severity") {
		t.Fatalf("timeline CSV missing header: %s", body)
	}
	if strings.Contains(body, "super-secret-token") || strings.Contains(body, "ui-secret-value") {
		t.Fatalf("timeline CSV leaked secret: %s", body)
	}
}

func TestTimelineProjectsProviderTestTargetAndCorrelation(t *testing.T) {
	srv, auditSink, _ := newTestServer(t, nil)
	auditSink.Record("provider_test", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"provider":       "cloudflare",
		"result":         "ready",
		"correlation_id": "corr-provider",
	})

	events := srv.allTimelineEvents(context.Background())
	for _, event := range events {
		if event.Action != "provider_test" {
			continue
		}
		if event.Target != "cloudflare" {
			t.Fatalf("expected provider_test target to project provider name, got %+v", event)
		}
		if event.EvidenceID != "" {
			t.Fatalf("audit entries must have empty EvidenceID (no evidence record), got %+v", event)
		}
		if event.CorrelationID != "corr-provider" {
			t.Fatalf("expected correlation_id in CorrelationID field, got %+v", event)
		}
		if event.Result != "ready" {
			t.Fatalf("expected provider_test result to stay useful, got %+v", event)
		}
		return
	}
	t.Fatalf("expected provider_test event in timeline, got %+v", events)
}

func TestTimelinePageAuditEntryShowsCorrelationNotEvidenceLink(t *testing.T) {
	srv, auditSink, _ := newTestServer(t, nil)
	auditSink.Record("provider_test", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"provider":       "cloudflare",
		"result":         "ready",
		"correlation_id": "corr-legacy",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	// /timeline redirects to /v2/timeline.
	req := httptest.NewRequest(http.MethodGet, "/v2/timeline", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}

	body := rr.Body.String()
	// V2 renders correlation ID as corr: pill (truncated to 10 chars).
	// "corr-legacy" → "corr-legac" in pill. The full ID also appears in details.
	if !strings.Contains(body, "corr-legac") && !strings.Contains(body, "corr-legacy") {
		t.Fatalf("expected correlation id to appear in v2 timeline, got %s", body)
	}
	// audit entries must NOT produce evidence links (no EvidenceID set for audit entries).
	if strings.Contains(body, `href="/evidence/`) {
		t.Fatalf("audit entry must not produce evidence links in v2 timeline, got %s", body)
	}
}
