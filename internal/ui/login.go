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
// Supports two authentication methods:
// 1. JSON with admin password ({"password": "..."}) - permanent password stored in SQLite
// 2. Form-encoded UI_SECRET (secret=...) - session token method
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

	// Fall back to form-based (UI_SECRET method)
	s.handleLoginForm(w, r)
}

// handleLoginJSON handles JSON-based admin password authentication.
// The permanent admin password hash is stored in SQLite (ui_settings key "admin_password_hash").
func (s *Server) handleLoginJSON(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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
		if s.logger != nil {
			s.logger.Error("load admin password hash", "err", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if !ok || hash == "" {
		// No permanent password set yet — setup not complete.
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !auth.VerifyPassword(hash, req.Password) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Generate session token
	sessionToken := generateSessionToken()
	s.mu.Lock()
	s.sessions[sessionToken] = time.Now().Add(sessionTTL)
	s.mu.Unlock()

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    sessionToken,
		MaxAge:   int(sessionTTL.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": sessionToken,
		"status":        "logged in",
		"redirect":      "/",
	})
}

// handleLoginForm handles form-based UI_SECRET authentication.
func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.audit.Record("login_error", map[string]string{"reason": "bad_form"})
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	secret := r.PostForm.Get("secret")
	expected, ok := s.secretProvider.Lookup("UI_SECRET")
	if !ok || expected == "" || subtleConstantTime(secret, expected) != 1 {
		s.audit.Record("login_failed", map[string]string{"reason": "invalid_secret"})
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	sessionToken := generateSessionToken()
	s.mu.Lock()
	s.sessions[sessionToken] = time.Now().Add(sessionTTL)
	s.pruneSessionsLocked(time.Now().UTC())
	s.mu.Unlock()
	http.SetCookie(w, s.sessionCookie(r, sessionToken))
	s.audit.Record("login_success", map[string]string{"actor": "local"})
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
