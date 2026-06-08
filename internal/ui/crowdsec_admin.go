package ui

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"strings"
	"time"
)

const crowdSecLAPIKey = "crowdsec.lapi_key"

// registerCrowdSecAdminRoutes wires the CrowdSec credential management routes
// into the server mux. Called from server.go after routes() is set up.
func (s *Server) registerCrowdSecAdminRoutes() {
	s.mux.Handle("POST /admin/crowdsec/key",
		s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleCrowdSecSetKey)))))
	s.mux.Handle("POST /admin/crowdsec/key/delete",
		s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleCrowdSecDeleteKey)))))
	s.mux.Handle("POST /admin/crowdsec/test",
		s.setupGuardMiddleware(s.forcePasswordChangeMiddleware(http.HandlerFunc(s.requireAuthHandler(s.handleCrowdSecTestConnection)))))
}

// handleCrowdSecSetKey stores or replaces the CrowdSec LAPI key in the encrypted CredentialStore.
func (s *Server) handleCrowdSecSetKey(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.credentialStore == nil {
		http.Error(w, "credential store not available", http.StatusServiceUnavailable)
		return
	}
	key := strings.TrimSpace(r.FormValue("lapi_key"))
	if key == "" {
		http.Error(w, "lapi key is required", http.StatusBadRequest)
		return
	}
	if err := s.credentialStore.Set(r.Context(), crowdSecLAPIKey, key, true); err != nil {
		s.logger.ErrorContext(r.Context(), "crowdsec lapi key store failed", "error", err)
		http.Error(w, "failed to store lapi key", http.StatusInternalServerError)
		return
	}
	s.logger.InfoContext(r.Context(), "crowdsec lapi key updated", "redacted", redactValue(key))
	if s.audit != nil {
		s.audit.Record("crowdsec_lapi_key_set", map[string]string{
			"result":         "redacted",
			"correlation_id": newUIEventID(),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleCrowdSecDeleteKey removes the CrowdSec LAPI key from the CredentialStore.
func (s *Server) handleCrowdSecDeleteKey(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.credentialStore == nil {
		http.Error(w, "credential store not available", http.StatusServiceUnavailable)
		return
	}
	if err := s.credentialStore.Delete(r.Context(), crowdSecLAPIKey); err != nil {
		s.logger.ErrorContext(r.Context(), "crowdsec lapi key delete failed", "error", err)
		http.Error(w, "failed to delete lapi key", http.StatusInternalServerError)
		return
	}
	s.logger.InfoContext(r.Context(), "crowdsec lapi key deleted")
	if s.audit != nil {
		s.audit.Record("crowdsec_lapi_key_deleted", map[string]string{
			"result":         "ok",
			"correlation_id": newUIEventID(),
		})
	}
	w.WriteHeader(http.StatusNoContent)
}

type crowdSecTestResult struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func writeCrowdSecJSON(w http.ResponseWriter, code int, status, message string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(crowdSecTestResult{Status: status, Message: message})
}

// handleCrowdSecTestConnection tests reachability of the CrowdSec LAPI.
// It uses net/http directly and never includes the key value in any response or log.
func (s *Server) handleCrowdSecTestConnection(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if s.credentialStore == nil {
		writeCrowdSecJSON(w, http.StatusServiceUnavailable, "error", "credential store not available")
		return
	}
	apiKey, ok, err := s.credentialStore.Lookup(r.Context(), crowdSecLAPIKey)
	if err != nil || !ok || apiKey == "" {
		writeCrowdSecJSON(w, http.StatusOK, "error", "LAPI key not configured")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:8080/v1/decisions?limit=1", nil)
	if err != nil {
		writeCrowdSecJSON(w, http.StatusOK, "error", "failed to build request")
		return
	}
	req.Header.Set("X-Api-Key", apiKey)

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		writeCrowdSecJSON(w, http.StatusOK, "error", fmt.Sprintf("LAPI unreachable: %v", sanitizeCrowdSecError(err)))
		return
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case http.StatusOK, http.StatusNoContent:
		if s.audit != nil {
			s.audit.Record("crowdsec_lapi_test", map[string]string{
				"result":         "reachable",
				"correlation_id": newUIEventID(),
			})
		}
		writeCrowdSecJSON(w, http.StatusOK, "ok", "LAPI reachable")
	case http.StatusUnauthorized:
		if s.audit != nil {
			s.audit.Record("crowdsec_lapi_test", map[string]string{
				"result":         "auth_failed",
				"correlation_id": newUIEventID(),
			})
		}
		writeCrowdSecJSON(w, http.StatusOK, "error", "LAPI key invalid (401)")
	default:
		if s.audit != nil {
			s.audit.Record("crowdsec_lapi_test", map[string]string{
				"result":         fmt.Sprintf("unexpected_status_%d", resp.StatusCode),
				"correlation_id": newUIEventID(),
			})
		}
		writeCrowdSecJSON(w, http.StatusOK, "error", fmt.Sprintf("LAPI returned unexpected status %d", resp.StatusCode))
	}
}

// sanitizeCrowdSecError strips potential secret material from error strings.
func sanitizeCrowdSecError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if idx := strings.IndexByte(msg, '?'); idx >= 0 {
		msg = msg[:idx]
	}
	return msg
}

// crowdSecAdminSection returns an HTML fragment for embedding in the admin panel.
func (s *Server) crowdSecAdminSection(ctx context.Context, csrfToken string) string {
	configured := credentialConfigured(ctx, s.credentialStore, crowdSecLAPIKey)

	var b strings.Builder
	b.WriteString(`<div class="panel">`)
	b.WriteString(`<h3>CrowdSec LAPI</h3>`)
	b.WriteString(`<div class="kv">`)
	b.WriteString(`<div class="row"><span>LAPI Key</span><span>`)
	if configured {
		b.WriteString(`configured`)
	} else {
		b.WriteString(`not configured`)
	}
	b.WriteString(`</span></div>`)
	b.WriteString(`</div>`)

	fmt.Fprintf(&b, `<form action="/admin/crowdsec/key" method="post">`+
		`<input type="hidden" name="csrf_token" value="%s">`+
		`<label for="lapi_key">Set / Replace LAPI Key</label>`+
		`<input id="lapi_key" name="lapi_key" type="password" autocomplete="off" placeholder="paste key">`+
		`<button type="submit">Save key</button>`+
		`</form>`,
		html.EscapeString(csrfToken),
	)

	if configured {
		fmt.Fprintf(&b, `<form action="/admin/crowdsec/key/delete" method="post" style="margin-top:.5rem">`+
			`<input type="hidden" name="csrf_token" value="%s">`+
			`<button type="submit" class="danger">Delete key</button>`+
			`</form>`,
			html.EscapeString(csrfToken),
		)
		fmt.Fprintf(&b, `<form action="/admin/crowdsec/test" method="post" style="margin-top:.5rem">`+
			`<input type="hidden" name="csrf_token" value="%s">`+
			`<button type="submit" class="secondary">Test connection</button>`+
			`</form>`,
			html.EscapeString(csrfToken),
		)
	}

	b.WriteString(`</div>`)
	return b.String()
}
