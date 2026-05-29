package v2

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jm/security-automation-go/internal/api/auth"
	apimodels "github.com/jm/security-automation-go/internal/api/models"
	"github.com/jm/security-automation-go/internal/policy/bundles/activation"
	"github.com/jm/security-automation-go/internal/policy/bundles/registry"
	"github.com/jm/security-automation-go/internal/policy/replay/recorder"
	"github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	rtmodels "github.com/jm/security-automation-go/internal/runtime/models"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/pool"
)

type V2Handler struct {
	ownerRes *ownership.Resolver
	gov      *governor.ResourceGovernor
	pool     *pool.Pool
	sm       *engine.StateMachine
	driftMem *memory.Store
	recorder *recorder.Recorder
	reg      *registry.Registry
	act      *activation.Manager
}

func NewV2Handler(or *ownership.Resolver, g *governor.ResourceGovernor, p *pool.Pool, sm *engine.StateMachine, dm *memory.Store, rec *recorder.Recorder, r *registry.Registry, a *activation.Manager) *V2Handler {
	return &V2Handler{
		ownerRes: or,
		gov:      g,
		pool:     p,
		sm:       sm,
		driftMem: dm,
		recorder: rec,
		reg:      r,
		act:      a,
	}
}

func (h *V2Handler) JSONResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apimodels.APIResponse{
		Success:   status < 400,
		Data:      data,
		Timestamp: time.Now().UTC(),
	})
}

func (h *V2Handler) ErrorResponse(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apimodels.APIResponse{
		Success: false,
		Error: &apimodels.APIError{
			Code:    code,
			Message: msg,
		},
		Timestamp: time.Now().UTC(),
	})
}

func (h *V2Handler) GetOwnershipClaims(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	claims := h.ownerRes.ListClaims()
	h.JSONResponse(w, http.StatusOK, claims)
}

func (h *V2Handler) GetGovernorStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	h.JSONResponse(w, http.StatusOK, map[string]any{
		"budgets":             h.gov.GetAllBudgetsStatus(),
		"cloudflare_pressure": h.gov.Pressure("cloudflare"),
	})
}

func (h *V2Handler) GetWorkersStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	h.JSONResponse(w, http.StatusOK, h.pool.Status())
}

func (h *V2Handler) GetDriftMemory(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	h.JSONResponse(w, http.StatusOK, map[string]string{"message": "drift memory exploration not fully implemented"})
}

func (h *V2Handler) GetPolicyEvidence(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeAuditRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	h.JSONResponse(w, http.StatusOK, h.recorder.List())
}

func (h *V2Handler) GetPolicyBundles(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	h.JSONResponse(w, http.StatusOK, h.reg.List())
}

func (h *V2Handler) RuntimePause(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeExecute) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	if err := h.sm.Transition(r.Context(), rtmodels.StatusPaused, "manual pause via API"); err != nil {
		h.ErrorResponse(w, http.StatusConflict, "TRANSITION_FAILED", err.Error())
		return
	}
	h.JSONResponse(w, http.StatusAccepted, map[string]string{"status": "paused"})
}

func (h *V2Handler) RuntimeResume(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeExecute) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	if err := h.sm.Transition(r.Context(), rtmodels.StatusIdle, "manual resume via API"); err != nil {
		h.ErrorResponse(w, http.StatusConflict, "TRANSITION_FAILED", err.Error())
		return
	}
	h.JSONResponse(w, http.StatusAccepted, map[string]string{"status": "idle"})
}
