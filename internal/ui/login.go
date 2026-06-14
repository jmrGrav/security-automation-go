package ui

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/jm/security-automation-go/internal/ui/auth"
)

// handleLogin processes POST /login requests.
// Supports both JSON ({"password": "..."}) and Form-encoded (password=...)
// authentication using the permanent admin password stored in SQLite.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.limiter.Allow(clientKey(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Try JSON first (admin password method)
	if r.Header.Get("Content-Type") == "application/json" {
		s.handleLoginJSON(w, r)
		return
	}

	// Fall back to form-based password login
	s.handleLoginForm(w, r)
}

// handleLoginJSON handles JSON-based admin password authentication.
// The permanent admin password hash is stored in SQLite (ui_settings key "admin_password_hash").
func (s *Server) handleLoginJSON(w http.ResponseWriter, r *http.Request) {
	eventID := newUIEventID()
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.auditRecord("login_error", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "bad_json",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	if s.setupStore == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}

	// Load permanent admin password hash from SQLite.
	hash, ok, err := s.setupStore.GetSetting(r.Context(), "admin_password_hash")
	if err != nil {
		s.auditRecord("login_error", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "db_error",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		if s.logger != nil {
			s.logger.Error("load admin password hash", "err", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok || hash == "" {
		// No permanent password set yet — setup not complete.
		s.auditRecord("login_failed", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "setup_incomplete",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !auth.VerifyPassword(hash, req.Password) {
		s.auditRecord("login_failed", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "invalid_password",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate session token
	sessionToken := generateSessionToken()
	s.mu.Lock()
	s.sessions[sessionToken] = time.Now().Add(sessionTTL)
	s.mu.Unlock()

	// Set session cookie
	s.setSessionCookie(w, sessionToken)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": sessionToken,
		"status":        "logged in",
		"redirect":      "/",
	})
	s.auditRecord("login_success", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "ui_session",
		"result":         "success",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
}

// handleLoginForm handles form-based admin password authentication.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	eventID := newUIEventID()
	if err := r.ParseForm(); err != nil {
		s.auditRecord("login_error", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "bad_form",
			"reason":         "bad_form",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	password := r.PostForm.Get("password")
	if password == "" {
		http.Error(w, "password required", http.StatusBadRequest)
		return
	}

	if s.setupStore == nil {
		http.Error(w, "not configured", http.StatusServiceUnavailable)
		return
	}

	// Load permanent admin password hash from SQLite.
	hash, ok, err := s.setupStore.GetSetting(r.Context(), "admin_password_hash")
	if err != nil {
		s.auditRecord("login_error", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "db_error",
			"reason":         "db_error",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok || hash == "" {
		s.auditRecord("login_failed", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "setup_incomplete",
			"reason":         "setup_incomplete",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !auth.VerifyPassword(hash, password) {
		s.auditRecord("login_failed", map[string]string{
			"actor":          "local",
			"source":         "ui",
			"target":         "ui_session",
			"result":         "invalid_password",
			"reason":         "invalid_password",
			"correlation_id": eventID,
			"event_id":       eventID,
		})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	sessionToken := generateSessionToken()
	s.mu.Lock()
	s.sessions[sessionToken] = time.Now().Add(sessionTTL)
	s.pruneSessionsLocked(time.Now().UTC())
	s.mu.Unlock()
	s.setSessionCookie(w, sessionToken)
	s.auditRecord("login_success", map[string]string{
		"actor":          "local",
		"source":         "ui",
		"target":         "ui_session",
		"result":         "success",
		"correlation_id": eventID,
		"event_id":       eventID,
	})
	http.Redirect(w, r, "/", http.StatusFound)
}

// generateSessionToken creates a cryptographically secure random session token.
// Uses base64 encoding of 32 random bytes for 256-bit entropy.
func generateSessionToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return base64.StdEncoding.EncodeToString(b)
}
