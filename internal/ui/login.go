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
// 1. JSON with bootstrap password ({"password": "..."}) - new method
// 2. Form-encoded UI_SECRET (secret=...) - legacy method for backward compatibility
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !s.limiter.Allow(clientKey(r)) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	// Try JSON first (bootstrap password method)
	if r.Header.Get("Content-Type") == "application/json" {
		s.handleLoginJSON(w, r)
		return
	}

	// Fall back to form-based (UI_SECRET method)
	s.handleLoginForm(w, r)
}

// handleLoginJSON handles JSON-based bootstrap password authentication.
func (s *Server) handleLoginJSON(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Load bootstrap state
	state, err := auth.GetBootstrapState(s.cfg.UI.AdminPasswordFile)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("failed to load bootstrap state", "err", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Check if bootstrap is still active
	if !state.IsBootstrap {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify password
	if !auth.VerifyPassword(state.PasswordHash, req.Password) {
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
		SameSite: http.SameSiteLaxMode,
		Path:     "/",
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"session_token": sessionToken,
		"status":        "logged in",
		"redirect":      "/ui/settings/password",
	})
}

// handleLoginForm handles form-based UI_SECRET authentication (legacy).
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
