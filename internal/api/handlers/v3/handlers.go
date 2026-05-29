package v3

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jm/security-automation-go/internal/api/auth"
	apimodels "github.com/jm/security-automation-go/internal/api/models"
	"github.com/jm/security-automation-go/internal/policy/admission"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/services/reporting"
)

type V3Handler struct {
	admission *admission.Controller
	evidence  reporting.EvidenceStore
	ownership *ownership.LineageQueryService
}

const maxOwnershipLineageLimit = 200

type ownershipLineagePageResponse struct {
	Items []ownership.LineageEvent `json:"items"`
	Next  *ownershipLineageCursor  `json:"next_cursor,omitempty"`
}

type ownershipLineageCursor struct {
	BeforeCreatedAt string `json:"before_created_at"`
	BeforeID        string `json:"before_id"`
}

func NewV3Handler(adm *admission.Controller, evidence reporting.EvidenceStore, ownershipService *ownership.LineageQueryService) *V3Handler {
	return &V3Handler{
		admission: adm,
		evidence:  evidence,
		ownership: ownershipService,
	}
}

func (h *V3Handler) JSONResponse(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(apimodels.APIResponse{
		Success:   status < 400,
		Data:      data,
		Timestamp: time.Now().UTC(),
	})
}

func (h *V3Handler) ErrorResponse(w http.ResponseWriter, status int, code, msg string) {
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

func (h *V3Handler) GetExplainDecision(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeAuditRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}

	evidenceID := r.URL.Query().Get("id")
	if evidenceID == "" {
		h.ErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "missing evidence id")
		return
	}

	graph, err := h.admission.ExplainDecision(r.Context(), evidenceID)
	if err != nil {
		h.ErrorResponse(w, http.StatusNotFound, "NOT_FOUND", err.Error())
		return
	}

	format := r.URL.Query().Get("format")
	if format == "mermaid" {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(graph.ToMermaid()))
		return
	}

	h.JSONResponse(w, http.StatusOK, graph)
}

func (h *V3Handler) GetSecurityEvidence(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeAuditRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}
	if h.evidence == nil {
		h.ErrorResponse(w, http.StatusServiceUnavailable, "UNAVAILABLE", "evidence store unavailable")
		return
	}

	evidenceID := r.PathValue("evidence_id")
	if evidenceID != "" {
		ev, found, err := h.evidence.Get(r.Context(), evidenceID)
		if err != nil {
			h.ErrorResponse(w, http.StatusInternalServerError, "EVIDENCE_READ_FAILED", err.Error())
			return
		}
		if !found {
			h.ErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "evidence not found")
			return
		}
		h.JSONResponse(w, http.StatusOK, ev)
		return
	}

	opts := reporting.EvidenceSearchOptions{
		IP:                r.URL.Query().Get("ip"),
		Source:            r.URL.Query().Get("source"),
		Decision:          r.URL.Query().Get("decision"),
		SuppressionReason: r.URL.Query().Get("reason"),
		Limit:             parsePositiveInt(r.URL.Query().Get("limit"), 20),
		Offset:            parsePositiveInt(r.URL.Query().Get("offset"), 0),
	}
	if from := r.URL.Query().Get("from"); from != "" {
		ts, err := time.Parse(time.RFC3339, from)
		if err != nil {
			h.ErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid from")
			return
		}
		opts.From = ts
	}
	if to := r.URL.Query().Get("to"); to != "" {
		ts, err := time.Parse(time.RFC3339, to)
		if err != nil {
			h.ErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid to")
			return
		}
		opts.To = ts
	}
	items, err := h.evidence.Search(r.Context(), opts)
	if err != nil {
		h.ErrorResponse(w, http.StatusInternalServerError, "EVIDENCE_SEARCH_FAILED", err.Error())
		return
	}
	h.JSONResponse(w, http.StatusOK, items)
}

func (h *V3Handler) GetExplainSecurityEvidence(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeAuditRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}
	if h.evidence == nil {
		h.ErrorResponse(w, http.StatusServiceUnavailable, "UNAVAILABLE", "evidence store unavailable")
		return
	}
	evidenceID := r.PathValue("evidence_id")
	if evidenceID == "" {
		h.ErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "missing evidence id")
		return
	}
	ev, found, err := h.evidence.Get(r.Context(), evidenceID)
	if err != nil {
		h.ErrorResponse(w, http.StatusInternalServerError, "EVIDENCE_READ_FAILED", err.Error())
		return
	}
	if !found {
		h.ErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "evidence not found")
		return
	}
	h.JSONResponse(w, http.StatusOK, reporting.ExplainEvidence(ev))
}

func (h *V3Handler) GetOwnershipLineage(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeAuditRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}
	if h.ownership == nil {
		h.ErrorResponse(w, http.StatusServiceUnavailable, "UNAVAILABLE", "ownership lineage store unavailable")
		return
	}

	eventID := r.PathValue("event_id")
	if eventID != "" {
		ev, found, err := h.ownership.Get(r.Context(), eventID)
		if err != nil {
			h.ErrorResponse(w, http.StatusInternalServerError, "OWNERSHIP_LINEAGE_READ_FAILED", err.Error())
			return
		}
		if !found {
			h.ErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "ownership lineage event not found")
			return
		}
		h.JSONResponse(w, http.StatusOK, ev)
		return
	}

	limit := clampOwnershipLineageLimit(parsePositiveInt(r.URL.Query().Get("limit"), 20))
	beforeCreatedAt, parseErr := parseOptionalRFC3339Nano(r.URL.Query().Get("before_created_at"))
	if parseErr != nil {
		h.ErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid before_created_at")
		return
	}
	items, err := h.ownership.Search(r.Context(), ownership.LineageSearchOptions{
		ScopeID:         r.URL.Query().Get("scope_id"),
		ResourceID:      r.URL.Query().Get("resource_id"),
		BeforeCreatedAt: beforeCreatedAt,
		BeforeID:        r.URL.Query().Get("before_id"),
		Limit:           limit,
	})
	if err != nil {
		h.ErrorResponse(w, http.StatusInternalServerError, "OWNERSHIP_LINEAGE_SEARCH_FAILED", err.Error())
		return
	}
	if len(items) > 0 {
		last := items[len(items)-1]
		w.Header().Set("X-Ownership-Lineage-Next-Created-At", last.CreatedAt.UTC().Format(time.RFC3339Nano))
		w.Header().Set("X-Ownership-Lineage-Next-ID", last.ID)
	}
	h.JSONResponse(w, http.StatusOK, items)
}

func (h *V3Handler) GetOwnershipLineagePage(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeAuditRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}
	if h.ownership == nil {
		h.ErrorResponse(w, http.StatusServiceUnavailable, "UNAVAILABLE", "ownership lineage store unavailable")
		return
	}

	limit := clampOwnershipLineageLimit(parsePositiveInt(r.URL.Query().Get("limit"), 20))
	beforeCreatedAt, parseErr := parseOptionalRFC3339Nano(r.URL.Query().Get("before_created_at"))
	if parseErr != nil {
		h.ErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "invalid before_created_at")
		return
	}
	items, err := h.ownership.Search(r.Context(), ownership.LineageSearchOptions{
		ScopeID:         r.URL.Query().Get("scope_id"),
		ResourceID:      r.URL.Query().Get("resource_id"),
		BeforeCreatedAt: beforeCreatedAt,
		BeforeID:        r.URL.Query().Get("before_id"),
		Limit:           limit,
	})
	if err != nil {
		h.ErrorResponse(w, http.StatusInternalServerError, "OWNERSHIP_LINEAGE_SEARCH_FAILED", err.Error())
		return
	}

	resp := ownershipLineagePageResponse{Items: items}
	if len(items) > 0 {
		last := items[len(items)-1]
		resp.Next = &ownershipLineageCursor{
			BeforeCreatedAt: last.CreatedAt.UTC().Format(time.RFC3339Nano),
			BeforeID:        last.ID,
		}
		w.Header().Set("X-Ownership-Lineage-Next-Created-At", resp.Next.BeforeCreatedAt)
		w.Header().Set("X-Ownership-Lineage-Next-ID", resp.Next.BeforeID)
	}
	h.JSONResponse(w, http.StatusOK, resp)
}

func (h *V3Handler) GetExplainOwnershipLineage(w http.ResponseWriter, r *http.Request) {
	id, _ := auth.FromContext(r.Context())
	if !id.HasScope(auth.ScopeAuditRead) {
		h.ErrorResponse(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
		return
	}
	if h.ownership == nil {
		h.ErrorResponse(w, http.StatusServiceUnavailable, "UNAVAILABLE", "ownership lineage store unavailable")
		return
	}
	eventID := r.PathValue("event_id")
	if eventID == "" {
		h.ErrorResponse(w, http.StatusBadRequest, "INVALID_REQUEST", "missing event id")
		return
	}
	ev, found, err := h.ownership.Get(r.Context(), eventID)
	if err != nil {
		h.ErrorResponse(w, http.StatusInternalServerError, "OWNERSHIP_LINEAGE_READ_FAILED", err.Error())
		return
	}
	if !found {
		h.ErrorResponse(w, http.StatusNotFound, "NOT_FOUND", "ownership lineage event not found")
		return
	}
	h.JSONResponse(w, http.StatusOK, ownership.ExplainLineageEvent(ev))
}

func parsePositiveInt(raw string, fallback int) int {
	if raw == "" {
		return fallback
	}
	var value int
	if _, err := fmt.Sscanf(raw, "%d", &value); err != nil || value < 0 {
		return fallback
	}
	return value
}

func clampOwnershipLineageLimit(limit int) int {
	if limit <= 0 {
		return 20
	}
	if limit > maxOwnershipLineageLimit {
		return maxOwnershipLineageLimit
	}
	return limit
}

func parseOptionalRFC3339Nano(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	ts, err := time.Parse(time.RFC3339Nano, raw)
	if err != nil {
		return time.Time{}, err
	}
	return ts.UTC(), nil
}
