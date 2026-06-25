package handlers

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/api/auth"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/health"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/runtime/status"
)

type fakeJournal struct {
	events []models.AuditEvent
}

func (f *fakeJournal) Append(e models.AuditEvent) error {
	f.events = append(f.events, e)
	return nil
}

func (f *fakeJournal) List() ([]models.AuditEvent, error) {
	return f.events, nil
}

var _ journal.JournalStore = (*fakeJournal)(nil)

func minimalCollector(t *testing.T) *status.Collector {
	t.Helper()
	tmpDir := t.TempDir()
	cb := breaker.New(5, time.Minute, time.Minute)
	hm := health.New(cb)
	ss := state.NewStateStore(tmpDir)
	return status.NewCollector("test", time.Now(), hm, cb, ss, "", tmpDir)
}

func withScope(r *http.Request, scopes ...auth.Scope) *http.Request {
	return r.WithContext(auth.WithIdentity(r.Context(), auth.Identity{OperatorID: "op", Scopes: scopes}))
}

// --- GetStatus ---

func TestGetStatus_NoScope_Returns403(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	// No identity injected → empty identity → no scope
	rr := httptest.NewRecorder()
	h.GetStatus(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGetStatus_WithScope_Returns200(t *testing.T) {
	h := NewBaseHandler(minimalCollector(t), &fakeJournal{}, nil)
	req := withScope(httptest.NewRequest(http.MethodGet, "/status", nil), auth.ScopeRuntimeRead)
	rr := httptest.NewRecorder()
	h.GetStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGetStatus_WrongScope_Returns403(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	req := withScope(httptest.NewRequest(http.MethodGet, "/status", nil), auth.ScopeAuditRead)
	rr := httptest.NewRecorder()
	h.GetStatus(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

// --- TriggerReconcile ---

func TestTriggerReconcile_NoScope_Returns403(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	body := `{"confirmed":true}`
	req := httptest.NewRequest(http.MethodPost, "/reconcile/run", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.TriggerReconcile(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestTriggerReconcile_NotConfirmed_Returns400(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	body := `{"confirmed":false}`
	req := withScope(httptest.NewRequest(http.MethodPost, "/reconcile/run", strings.NewReader(body)), auth.ScopeRuntimeExecute)
	rr := httptest.NewRecorder()
	h.TriggerReconcile(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTriggerReconcile_MalformedJSON_Returns400(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	req := withScope(httptest.NewRequest(http.MethodPost, "/reconcile/run", strings.NewReader("{bad json")), auth.ScopeRuntimeExecute)
	rr := httptest.NewRecorder()
	h.TriggerReconcile(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestTriggerReconcile_Confirmed_Returns501(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	body := `{"confirmed":true,"reason":"manual test"}`
	req := withScope(httptest.NewRequest(http.MethodPost, "/reconcile/run", strings.NewReader(body)), auth.ScopeRuntimeExecute)
	rr := httptest.NewRecorder()
	h.TriggerReconcile(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- GetAuditEvents ---

func TestGetAuditEvents_NoScope_Returns403(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	req := httptest.NewRequest(http.MethodGet, "/audit/events", nil)
	rr := httptest.NewRecorder()
	h.GetAuditEvents(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGetAuditEvents_WithScope_Returns200(t *testing.T) {
	j := &fakeJournal{}
	h := NewBaseHandler(nil, j, nil)
	req := withScope(httptest.NewRequest(http.MethodGet, "/audit/events", nil), auth.ScopeAuditRead)
	rr := httptest.NewRecorder()
	h.GetAuditEvents(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- ReleaseQuarantine ---

func TestReleaseQuarantine_NoScope_Returns403(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	req := httptest.NewRequest(http.MethodPost, "/quarantine/release", nil)
	rr := httptest.NewRecorder()
	h.ReleaseQuarantine(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestReleaseQuarantine_WithScope_Returns501(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	req := withScope(httptest.NewRequest(http.MethodPost, "/quarantine/release", nil), auth.ScopeQuarantineManage)
	rr := httptest.NewRecorder()
	h.ReleaseQuarantine(rr, req)
	if rr.Code != http.StatusNotImplemented {
		t.Errorf("expected 501, got %d", rr.Code)
	}
}

// --- Response format ---

func TestJSONResponse_ContentType(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	rr := httptest.NewRecorder()
	h.JSONResponse(rr, http.StatusOK, map[string]string{"k": "v"})
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
	var payload map[string]any
	if err := json.NewDecoder(bytes.NewReader(rr.Body.Bytes())).Decode(&payload); err != nil {
		t.Fatalf("response not valid JSON: %v", err)
	}
	if payload["success"] != true {
		t.Errorf("expected success=true")
	}
}

func TestErrorResponse_ContentType(t *testing.T) {
	h := NewBaseHandler(nil, &fakeJournal{}, nil)
	rr := httptest.NewRecorder()
	h.ErrorResponse(rr, http.StatusBadRequest, "TEST_CODE", "test message")
	if ct := rr.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("expected application/json, got %s", ct)
	}
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}
