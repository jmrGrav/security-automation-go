package v2

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jm/security-automation-go/internal/api/auth"
	"github.com/jm/security-automation-go/internal/policy/bundles/registry"
	"github.com/jm/security-automation-go/internal/policy/replay/recorder"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/budget"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/pool"
	"github.com/jm/security-automation-go/internal/runtime/state"
)

type fakeJournalV2 struct{}

func (f *fakeJournalV2) Append(models.AuditEvent) error     { return nil }
func (f *fakeJournalV2) List() ([]models.AuditEvent, error) { return nil, nil }

var _ journal.JournalStore = (*fakeJournalV2)(nil)

func withScope(r *http.Request, scopes ...auth.Scope) *http.Request {
	return r.WithContext(auth.WithIdentity(r.Context(), auth.Identity{OperatorID: "op", Scopes: scopes}))
}

func minimalHandler(t *testing.T) *V2Handler {
	t.Helper()
	tmpDir := t.TempDir()
	reg := registry.New()
	rec := recorder.New(&fakeJournalV2{}, slog.Default())
	gov := governor.New(slog.Default())
	bm := budget.NewManager()
	p := pool.New(1, bm, slog.Default())
	t.Cleanup(func() { p.Close() })
	ss := state.NewStateStore(tmpDir)
	sm := engine.NewStateMachine(ss, slog.Default())
	or := ownership.NewResolver()
	return NewV2Handler(or, gov, p, sm, nil, rec, reg, nil)
}

// --- GetOwnershipClaims ---

func TestGetOwnershipClaims_NoScope_Returns403(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/ownership/claims", nil)
	rr := httptest.NewRecorder()
	h.GetOwnershipClaims(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGetOwnershipClaims_WithScope_Returns200(t *testing.T) {
	h := minimalHandler(t)
	req := withScope(httptest.NewRequest(http.MethodGet, "/ownership/claims", nil), auth.ScopeRuntimeRead)
	rr := httptest.NewRecorder()
	h.GetOwnershipClaims(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- GetGovernorStatus ---

func TestGetGovernorStatus_NoScope_Returns403(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/governor/budgets", nil)
	rr := httptest.NewRecorder()
	h.GetGovernorStatus(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGetGovernorStatus_WithScope_Returns200(t *testing.T) {
	h := minimalHandler(t)
	req := withScope(httptest.NewRequest(http.MethodGet, "/governor/budgets", nil), auth.ScopeRuntimeRead)
	rr := httptest.NewRecorder()
	h.GetGovernorStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- GetWorkersStatus ---

func TestGetWorkersStatus_NoScope_Returns403(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/workers", nil)
	rr := httptest.NewRecorder()
	h.GetWorkersStatus(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGetWorkersStatus_WithScope_Returns200(t *testing.T) {
	h := minimalHandler(t)
	req := withScope(httptest.NewRequest(http.MethodGet, "/workers", nil), auth.ScopeRuntimeRead)
	rr := httptest.NewRecorder()
	h.GetWorkersStatus(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- GetDriftMemory ---

func TestGetDriftMemory_NoScope_Returns403(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/drift/memory", nil)
	rr := httptest.NewRecorder()
	h.GetDriftMemory(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGetDriftMemory_WithScope_Returns200(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := withScope(httptest.NewRequest(http.MethodGet, "/drift/memory", nil), auth.ScopeRuntimeRead)
	rr := httptest.NewRecorder()
	h.GetDriftMemory(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- GetPolicyEvidence ---

func TestGetPolicyEvidence_NoScope_Returns403(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/policy/evidence", nil)
	rr := httptest.NewRecorder()
	h.GetPolicyEvidence(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGetPolicyEvidence_WithScope_Returns200(t *testing.T) {
	h := minimalHandler(t)
	req := withScope(httptest.NewRequest(http.MethodGet, "/policy/evidence", nil), auth.ScopeAuditRead)
	rr := httptest.NewRecorder()
	h.GetPolicyEvidence(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- GetPolicyBundles ---

func TestGetPolicyBundles_NoScope_Returns403(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/policy/bundles", nil)
	rr := httptest.NewRecorder()
	h.GetPolicyBundles(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestGetPolicyBundles_WithScope_Returns200(t *testing.T) {
	h := minimalHandler(t)
	req := withScope(httptest.NewRequest(http.MethodGet, "/policy/bundles", nil), auth.ScopeRuntimeRead)
	rr := httptest.NewRecorder()
	h.GetPolicyBundles(rr, req)
	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
}

// --- RuntimePause ---

func TestRuntimePause_NoScope_Returns403(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/runtime/pause", nil)
	rr := httptest.NewRecorder()
	h.RuntimePause(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRuntimePause_WithScope_Returns202(t *testing.T) {
	h := minimalHandler(t)
	req := withScope(httptest.NewRequest(http.MethodPost, "/runtime/pause", nil), auth.ScopeRuntimeExecute)
	rr := httptest.NewRecorder()
	h.RuntimePause(rr, req)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202, got %d: %s", rr.Code, rr.Body.String())
	}
}

// --- RuntimeResume ---

func TestRuntimeResume_NoScope_Returns403(t *testing.T) {
	h := NewV2Handler(nil, nil, nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/runtime/resume", nil)
	rr := httptest.NewRecorder()
	h.RuntimeResume(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", rr.Code)
	}
}

func TestRuntimeResume_AfterPause_Returns202(t *testing.T) {
	h := minimalHandler(t)
	// First pause
	ctx := auth.WithIdentity(httptest.NewRequest(http.MethodPost, "/runtime/pause", nil).Context(),
		auth.Identity{OperatorID: "op", Scopes: []auth.Scope{auth.ScopeRuntimeExecute}})
	pauseReq := httptest.NewRequest(http.MethodPost, "/runtime/pause", nil).WithContext(ctx)
	h.RuntimePause(httptest.NewRecorder(), pauseReq)

	// Then resume
	resumeReq := withScope(httptest.NewRequest(http.MethodPost, "/runtime/resume", nil), auth.ScopeRuntimeExecute)
	rr := httptest.NewRecorder()
	h.RuntimeResume(rr, resumeReq)
	if rr.Code != http.StatusAccepted {
		t.Errorf("expected 202 after resume, got %d: %s", rr.Code, rr.Body.String())
	}
}
