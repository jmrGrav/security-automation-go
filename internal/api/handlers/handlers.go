package handlers

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/jm/security-automation-go/internal/api/auth"
	"github.com/jm/security-automation-go/internal/api/models"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/quarantine"
	"github.com/jm/security-automation-go/internal/runtime/status"
)

type BaseHandler struct {
	collector  *status.Collector
	journal    journal.JournalStore
	quarantine *quarantine.Store
}

func NewBaseHandler(collector *status.Collector, journal journal.JournalStore, qStore *quarantine.Store) *BaseHandler {
	return &BaseHandler{
		collector:  collector,
		journal:    journal,
		quarantine: qStore,
	}
}

func (h *BaseHandler) JSONResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.APIResponse{
		Success:   status < 400,
		Data:      data,
		Timestamp: time.Now().UTC(),
	})
}

func (h *BaseHandler) ErrorResponse(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(models.APIResponse{
		Success: false,
		Error: &models.APIError{
			Code:    code,
			Message: msg,
		},
		Timestamp: time.Now().UTC(),
	})
}

func (h *BaseHandler) GetStatus(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	res, err := h.collector.Collect()
	if err != nil {
		h.ErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	h.JSONResponse(w, http.StatusOK, res)
}

func (h *BaseHandler) TriggerReconcile(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeRuntimeExecute) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	var payload models.ConfirmationPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		h.ErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "malformed confirmation payload")
		return
	}

	if !payload.Confirmed {
		h.ErrorResponse(w, http.StatusBadRequest, "CONFIRMATION_REQUIRED", "explicit confirmation is required")
		return
	}

	// Daemon signal channel not yet wired — planned for v1.8.x.
	h.ErrorResponse(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "on-demand reconciliation trigger is not yet available in this build")
}

func (h *BaseHandler) GetAuditEvents(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeAuditRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	events, err := h.journal.List()
	if err != nil {
		h.ErrorResponse(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
		return
	}
	h.JSONResponse(w, http.StatusOK, events)
}

func (h *BaseHandler) ReleaseQuarantine(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeQuarantineManage) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	// Quarantine release not yet implemented — planned for v1.8.x.
	h.ErrorResponse(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "quarantine release is not yet available in this build")
}
