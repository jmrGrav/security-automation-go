package v3

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/api/auth"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type fakeEvidenceStore struct {
	items map[string]reporting.DecisionEvidence
}

func (s fakeEvidenceStore) Append(context.Context, reporting.DecisionEvidence) error { return nil }
func (s fakeEvidenceStore) List(context.Context, int) ([]reporting.DecisionEvidence, error) {
	return nil, nil
}
func (s fakeEvidenceStore) Get(_ context.Context, evidenceID string) (reporting.DecisionEvidence, bool, error) {
	ev, ok := s.items[evidenceID]
	return ev, ok, nil
}
func (s fakeEvidenceStore) Search(_ context.Context, opts reporting.EvidenceSearchOptions) ([]reporting.DecisionEvidence, error) {
	var out []reporting.DecisionEvidence
	for _, item := range s.items {
		if opts.IP != "" && item.IP != opts.IP {
			continue
		}
		out = append(out, item)
	}
	return out, nil
}

func (s fakeEvidenceStore) Count(_ context.Context, opts reporting.EvidenceSearchOptions) (int, error) {
	out, err := s.Search(context.Background(), opts)
	return len(out), err
}

type fakeLineageStore struct {
	items     map[string]ownership.LineageEvent
	lastLimit int
}

func (s fakeLineageStore) GetLineage(_ context.Context, eventID string) (ownership.LineageEvent, bool, error) {
	ev, ok := s.items[eventID]
	return ev, ok, nil
}

func (s fakeLineageStore) ListLineage(_ context.Context, scopeID string, resourceID string, limit int) ([]ownership.LineageEvent, error) {
	return s.ListLineageCursor(context.Background(), scopeID, resourceID, time.Time{}, "", limit)
}

func (s fakeLineageStore) ListLineageCursor(_ context.Context, scopeID string, resourceID string, beforeCreatedAt time.Time, beforeID string, limit int) ([]ownership.LineageEvent, error) {
	s.lastLimit = limit
	out := make([]ownership.LineageEvent, 0, len(s.items))
	for _, ev := range s.items {
		if scopeID != "" && ev.ScopeID != scopeID {
			continue
		}
		if resourceID != "" && ev.ResourceID != resourceID {
			continue
		}
		if !beforeCreatedAt.IsZero() {
			if ev.CreatedAt.After(beforeCreatedAt) {
				continue
			}
			if ev.CreatedAt.Equal(beforeCreatedAt) && beforeID != "" && ev.ID >= beforeID {
				continue
			}
		}
		out = append(out, ev)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out, nil
}

func TestGetSecurityEvidenceAndExplain(t *testing.T) {
	store := fakeEvidenceStore{
		items: map[string]reporting.DecisionEvidence{
			"ev-1": {
				EvidenceID:        "ev-1",
				Timestamp:         time.Date(2026, 5, 27, 16, 0, 0, 0, time.UTC),
				Source:            "cloudflare_waf",
				IP:                "198.51.100.10",
				Decision:          "suppressed",
				AbuseType:         "wordpress_probe",
				SuppressionReason: "abuseipdb_recently_reported",
			},
		},
	}
	h := NewV3Handler(nil, store, nil)

	req := httptest.NewRequest(http.MethodGet, "/security/evidence/ev-1", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), auth.Identity{Scopes: []auth.Scope{auth.ScopeAuditRead}}))
	req.SetPathValue("evidence_id", "ev-1")
	rr := httptest.NewRecorder()
	h.GetSecurityEvidence(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/security/evidence/ev-1/explain", nil)
	req2 = req2.WithContext(auth.WithIdentity(req2.Context(), auth.Identity{Scopes: []auth.Scope{auth.ScopeAuditRead}}))
	req2.SetPathValue("evidence_id", "ev-1")
	rr2 := httptest.NewRecorder()
	h.GetExplainSecurityEvidence(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("unexpected explain status: %d", rr2.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rr2.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if payload["success"] != true {
		t.Fatalf("unexpected payload: %s", rr2.Body.String())
	}
}

func TestGetOwnershipLineageAndExplain(t *testing.T) {
	lineage := fakeLineageStore{
		items: map[string]ownership.LineageEvent{
			"own-1": {
				ID:           "own-1",
				ScopeID:      "scope-a",
				ResourceID:   "res-1",
				DomainID:     "cf-sync",
				EventType:    ownership.LineageEventClaim,
				Decision:     "claim_set",
				DecisionHash: "h1",
				CreatedAt:    time.Date(2026, 5, 29, 10, 0, 0, 0, time.UTC),
			},
		},
	}
	h := NewV3Handler(nil, fakeEvidenceStore{}, ownership.NewLineageQueryService(lineage))

	req := httptest.NewRequest(http.MethodGet, "/security/ownership/lineage/own-1", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), auth.Identity{Scopes: []auth.Scope{auth.ScopeAuditRead}}))
	req.SetPathValue("event_id", "own-1")
	rr := httptest.NewRecorder()
	h.GetOwnershipLineage(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/security/ownership/lineage/own-1/explain", nil)
	req2 = req2.WithContext(auth.WithIdentity(req2.Context(), auth.Identity{Scopes: []auth.Scope{auth.ScopeAuditRead}}))
	req2.SetPathValue("event_id", "own-1")
	rr2 := httptest.NewRecorder()
	h.GetExplainOwnershipLineage(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("unexpected explain status: %d", rr2.Code)
	}

	reqList := httptest.NewRequest(http.MethodGet, "/security/ownership/lineage?scope_id=scope-a&limit=1", nil)
	reqList = reqList.WithContext(auth.WithIdentity(reqList.Context(), auth.Identity{Scopes: []auth.Scope{auth.ScopeAuditRead}}))
	rrList := httptest.NewRecorder()
	h.GetOwnershipLineage(rrList, reqList)
	if rrList.Code != http.StatusOK {
		t.Fatalf("unexpected list status: %d", rrList.Code)
	}
	if rrList.Header().Get("X-Ownership-Lineage-Next-Created-At") == "" || rrList.Header().Get("X-Ownership-Lineage-Next-ID") == "" {
		t.Fatalf("expected ownership lineage next cursor headers, got %+v", rrList.Header())
	}
}

func TestGetOwnershipLineagePage(t *testing.T) {
	lineage := fakeLineageStore{
		items: map[string]ownership.LineageEvent{
			"own-2": {
				ID: "own-2", ScopeID: "scope-a", ResourceID: "res-1", DomainID: "cf-sync",
				EventType: ownership.LineageEventClaim, DecisionHash: "h2",
				CreatedAt: time.Date(2026, 5, 29, 11, 0, 0, 0, time.UTC),
			},
		},
	}
	h := NewV3Handler(nil, fakeEvidenceStore{}, ownership.NewLineageQueryService(lineage))

	req := httptest.NewRequest(http.MethodGet, "/security/ownership/lineage/page?scope_id=scope-a&limit=1000", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), auth.Identity{Scopes: []auth.Scope{auth.ScopeAuditRead}}))
	rr := httptest.NewRecorder()
	h.GetOwnershipLineagePage(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("unexpected page status: %d", rr.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal page response: %v", err)
	}
	data, ok := payload["data"].(map[string]any)
	if !ok {
		t.Fatalf("unexpected data payload: %s", rr.Body.String())
	}
	if _, ok := data["next_cursor"]; !ok {
		t.Fatalf("expected next_cursor in page response: %s", rr.Body.String())
	}
}

func TestGetOwnershipLineagePage_InvalidCursor(t *testing.T) {
	lineage := fakeLineageStore{items: map[string]ownership.LineageEvent{}}
	h := NewV3Handler(nil, fakeEvidenceStore{}, ownership.NewLineageQueryService(lineage))

	req := httptest.NewRequest(http.MethodGet, "/security/ownership/lineage/page?before_created_at=bad-date", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), auth.Identity{Scopes: []auth.Scope{auth.ScopeAuditRead}}))
	rr := httptest.NewRecorder()
	h.GetOwnershipLineagePage(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for invalid cursor, got %d", rr.Code)
	}
}

func TestClampOwnershipLineageLimit(t *testing.T) {
	if got := clampOwnershipLineageLimit(-1); got != 20 {
		t.Fatalf("expected fallback 20, got %d", got)
	}
	if got := clampOwnershipLineageLimit(1000); got != 200 {
		t.Fatalf("expected clamped 200, got %d", got)
	}
	if got := clampOwnershipLineageLimit(50); got != 50 {
		t.Fatalf("expected 50, got %d", got)
	}
}
