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
	"github.com/jm/security-automation-go/internal/cloudflare/enforcementlog"
)

type fakeEnforcementEventStore struct {
	events      []enforcementlog.Event
	lastSuccess enforcementlog.Event
	hasSuccess  bool
	lastFailure enforcementlog.Event
	hasFailure  bool
	err         error
}

func (s *fakeEnforcementEventStore) Append(context.Context, enforcementlog.Event) error { return nil }

func (s *fakeEnforcementEventStore) Recent(context.Context, int) ([]enforcementlog.Event, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.events, nil
}

func (s *fakeEnforcementEventStore) LastSuccess(context.Context) (enforcementlog.Event, bool, error) {
	return s.lastSuccess, s.hasSuccess, nil
}

func (s *fakeEnforcementEventStore) LastFailure(context.Context) (enforcementlog.Event, bool, error) {
	return s.lastFailure, s.hasFailure, nil
}

func TestCFSyncView_NotWired(t *testing.T) {
	s := &Server{}
	view := s.buildCFSyncView(context.Background())
	if view.Wired {
		t.Error("expected Wired=false when neither store is configured")
	}
	if view.Error != "" {
		t.Errorf("unexpected error: %s", view.Error)
	}
}

func TestCFSyncView_NoShadowDataNoRegression(t *testing.T) {
	// With cf-shadow fully decommissioned, the lifecycle + event stores
	// are wired but empty (no bans yet). The page must reflect this real
	// "no activity yet" state, not regress to "waiting forever".
	lifecycle := &fakeBanLifecycleStore{}
	events := &fakeEnforcementEventStore{}
	s := &Server{banLifecycleStore: lifecycle, enforcementEventStore: events}

	view := s.buildCFSyncView(context.Background())
	if !view.Wired {
		t.Fatal("expected Wired=true when stores are configured, even with no data yet")
	}
	if view.ActiveBanCount != 0 {
		t.Errorf("expected ActiveBanCount=0, got %d", view.ActiveBanCount)
	}
	if len(view.Events) != 0 {
		t.Errorf("expected no events, got %d", len(view.Events))
	}
	if view.HasLastSuccess || view.HasLastFailure {
		t.Error("expected no last-success/last-failure with empty store")
	}
}

func TestCFSyncView_RealBanRecorded(t *testing.T) {
	now := time.Now().UTC()
	lifecycle := &fakeBanLifecycleStore{entries: []banlifecycle.Entry{
		{IP: "203.0.113.5", Status: banlifecycle.StatusActive, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	}}
	events := &fakeEnforcementEventStore{
		events: []enforcementlog.Event{
			{OccurredAt: now, Action: enforcementlog.ActionBanApplied, IP: "203.0.113.5", Reason: "confidence_100", Success: true, Duration: 120 * time.Millisecond},
		},
		lastSuccess: enforcementlog.Event{OccurredAt: now, Action: enforcementlog.ActionBanApplied, IP: "203.0.113.5"},
		hasSuccess:  true,
	}
	s := &Server{banLifecycleStore: lifecycle, enforcementEventStore: events}

	view := s.buildCFSyncView(context.Background())
	if view.ActiveBanCount != 1 {
		t.Errorf("expected ActiveBanCount=1, got %d", view.ActiveBanCount)
	}
	if !view.HasLastSuccess || view.LastSuccessIP != "203.0.113.5" {
		t.Errorf("expected last success for 203.0.113.5, got %+v", view)
	}
	if len(view.Events) != 1 || view.Events[0].IP != "203.0.113.5" {
		t.Errorf("expected 1 event for 203.0.113.5, got %v", view.Events)
	}
}

func TestCFSyncView_BanExpiredAndCleaned(t *testing.T) {
	// buildCFSyncView counts expirations from Recent (full history, all
	// statuses), not from Active (which fakeBanLifecycleStore — like the
	// real BanLifecycleStore.Active query — only ever contains active
	// entries in production; the fake just returns whatever was seeded).
	now := time.Now().UTC()
	lifecycle := &fakeBanLifecycleStore{entries: []banlifecycle.Entry{
		{IP: "198.51.100.9", Status: banlifecycle.StatusExpiredCleaned, CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
	}}
	events := &fakeEnforcementEventStore{
		events: []enforcementlog.Event{
			{OccurredAt: now, Action: enforcementlog.ActionBanRemoved, IP: "198.51.100.9", Reason: "ban expired", Success: true},
		},
	}
	s := &Server{banLifecycleStore: lifecycle, enforcementEventStore: events}

	view := s.buildCFSyncView(context.Background())
	if view.ExpirationsHandled != 1 {
		t.Errorf("expected ExpirationsHandled=1, got %d", view.ExpirationsHandled)
	}
	if len(view.Events) != 1 || view.Events[0].Action != enforcementlog.ActionBanRemoved {
		t.Errorf("expected 1 ban_removed event, got %v", view.Events)
	}
}

func TestCFSyncView_BanRemoved(t *testing.T) {
	now := time.Now().UTC()
	events := &fakeEnforcementEventStore{
		events: []enforcementlog.Event{
			{OccurredAt: now, Action: enforcementlog.ActionBanRemoved, IP: "10.0.0.5", Success: true},
		},
	}
	s := &Server{banLifecycleStore: &fakeBanLifecycleStore{}, enforcementEventStore: events}

	view := s.buildCFSyncView(context.Background())
	if len(view.Events) != 1 || view.Events[0].IP != "10.0.0.5" {
		t.Errorf("expected ban_removed event for 10.0.0.5, got %v", view.Events)
	}
}

func TestCFSyncView_FailedEnforcementCall(t *testing.T) {
	now := time.Now().UTC()
	events := &fakeEnforcementEventStore{
		lastFailure: enforcementlog.Event{OccurredAt: now, IP: "203.0.113.99", Error: "cloudflare: 500 internal error"},
		hasFailure:  true,
	}
	s := &Server{banLifecycleStore: &fakeBanLifecycleStore{}, enforcementEventStore: events}

	view := s.buildCFSyncView(context.Background())
	if !view.HasLastFailure {
		t.Fatal("expected HasLastFailure=true")
	}
	if view.LastFailureIP != "203.0.113.99" || view.LastFailureError == "" {
		t.Errorf("unexpected failure view: %+v", view)
	}
}

func TestCFSyncView_StoreError(t *testing.T) {
	events := &fakeEnforcementEventStore{err: errors.New("db unavailable")}
	s := &Server{banLifecycleStore: &fakeBanLifecycleStore{}, enforcementEventStore: events}

	view := s.buildCFSyncView(context.Background())
	if !view.Wired {
		t.Fatal("expected Wired=true even on a query error")
	}
	if view.Error == "" {
		t.Error("expected Error to be set when Recent fails")
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
	if !strings.Contains(body, "not available") {
		t.Error("expected not-wired message")
	}
}

func TestCFSyncPage_RendersActivity(t *testing.T) {
	now := time.Now().UTC()
	view := CFSyncView{
		Wired:          true,
		MutationsOn:    true,
		ActiveBanCount: 3,
		HasLastSuccess: true,
		LastSuccessAt:  now,
		LastSuccessIP:  "1.2.3.4",
		Events: []CFEnforcementEventView{
			{OccurredAt: now, Action: enforcementlog.ActionBanApplied, IP: "1.2.3.4", Reason: "confidence_100", Success: true, Duration: 50 * time.Millisecond},
		},
	}
	comp := CFSyncPage(view)
	w := httptest.NewRecorder()
	_ = comp.Render(context.Background(), w)
	body := w.Body.String()

	if !strings.Contains(body, "1.2.3.4") {
		t.Error("expected IP in body")
	}
	if !strings.Contains(body, "MUTATIONS ON") {
		t.Error("expected mutations-on badge")
	}
}

func TestCFSyncPage_RendersFailure(t *testing.T) {
	now := time.Now().UTC()
	view := CFSyncView{
		Wired:            true,
		HasLastFailure:   true,
		LastFailureAt:    now,
		LastFailureIP:    "9.9.9.9",
		LastFailureError: "cloudflare: rate limited",
		Events: []CFEnforcementEventView{
			{OccurredAt: now, Action: enforcementlog.ActionBanFailed, IP: "9.9.9.9", Success: false, Error: "cloudflare: rate limited"},
		},
	}
	comp := CFSyncPage(view)
	w := httptest.NewRecorder()
	_ = comp.Render(context.Background(), w)
	body := w.Body.String()

	if !strings.Contains(body, "9.9.9.9") {
		t.Error("expected failed IP in body")
	}
	if !strings.Contains(body, "FAILED") {
		t.Error("expected FAILED badge")
	}
}

func TestHandleCFSyncPage_HTTPIntegration(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	now := time.Now().UTC()
	srv.banLifecycleStore = &fakeBanLifecycleStore{entries: []banlifecycle.Entry{
		{IP: "10.0.0.1", Status: banlifecycle.StatusActive, CreatedAt: now, ExpiresAt: now.Add(time.Hour)},
	}}
	srv.enforcementEventStore = &fakeEnforcementEventStore{
		events: []enforcementlog.Event{
			{OccurredAt: now, Action: enforcementlog.ActionBanApplied, IP: "10.0.0.1", Success: true},
		},
	}

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
	if !strings.Contains(body, "10.0.0.1") {
		t.Error("expected IP in sync page")
	}
}
