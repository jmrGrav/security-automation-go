package ui

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/ui/auth"
)

const minPasswordLength = 16

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Verify authentication
	_, ok := s.getSession(r)
	if !ok {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if !s.validCSRF(r) {
		http.Error(w, "csrf required", http.StatusForbidden)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
		ConfirmPassword string `json:"confirm_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}

	// Validate new passwords match
	if req.NewPassword != req.ConfirmPassword {
		http.Error(w, "passwords do not match", http.StatusBadRequest)
		return
	}

	// Validate password complexity
	if len(req.NewPassword) < minPasswordLength {
		http.Error(w, fmt.Sprintf("password must be at least %d characters", minPasswordLength), http.StatusBadRequest)
		return
	}
	if !hasPasswordComplexity(req.NewPassword) {
		http.Error(w, "password must contain uppercase, lowercase, digits, and symbols", http.StatusBadRequest)
		return
	}

	// Load current bootstrap state
	state, err := auth.GetBootstrapState(s.cfg.UI.AdminPasswordFile)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("load bootstrap state", "err", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Verify current password
	if !auth.VerifyPassword(state.PasswordHash, req.CurrentPassword) {
		http.Error(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}

	// Hash and store new password
	newHash, err := auth.HashPassword(req.NewPassword)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("hash password", "err", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Update bootstrap state: set new hash and clear bootstrap flag
	state.PasswordHash = newHash
	state.IsBootstrap = false

	if err := auth.SaveBootstrapState(s.cfg.UI.AdminPasswordFile, state); err != nil {
		if s.logger != nil {
			s.logger.Error("save bootstrap state", "err", err)
		}
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Audit: password_changed
	if s.audit != nil {
		s.audit.Record("password_changed", map[string]string{
			"bootstrap_cleared": "true",
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":   "success",
		"redirect": "/ui/dashboard",
	})
}

func hasPasswordComplexity(pwd string) bool {
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSymbol := false

	for _, c := range pwd {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()_+-=[]{}|;:,.<>?", c):
			hasSymbol = true
		}
	}
	return hasUpper && hasLower && hasDigit && hasSymbol
}

func (s *Server) getSession(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}

	s.mu.Lock()
	expiry, ok := s.sessions[cookie.Value]
	if ok && time.Now().After(expiry) {
		delete(s.sessions, cookie.Value)
		ok = false
	}
	s.mu.Unlock()

	if !ok {
		return "", false
	}

	return cookie.Value, true
}
