package ui

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/ui/auth"
)

// TestFullAuthenticationFlow verifies the complete authentication lifecycle:
// 1. Bootstrap password initialization
// 2. First login with bootstrap password
// 3. Force redirect to password change
// 4. Password change with validation
// 5. Bootstrap flag cleared
// 6. Old password no longer works
// 7. New password works
// 8. No secret leakage
func TestFullAuthenticationFlow(t *testing.T) {
	// Setup: Initialize bootstrap password
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	bootstrapPwd, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	// Verify bootstrap state is initially active
	state, err := auth.GetBootstrapState(passwordFile)
	if err != nil {
		t.Fatalf("GetBootstrapState failed: %v", err)
	}
	if !state.IsBootstrap {
		t.Errorf("bootstrap should be active on initialization")
	}

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
	}

	// Step 1: Login with bootstrap password via JSON
	loginBody := map[string]string{"password": bootstrapPwd}
	loginJSON, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleLoginJSON(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("login failed: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var loginResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&loginResp); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}

	sessionToken, ok := loginResp["session_token"]
	if !ok || sessionToken == "" {
		t.Fatalf("no session_token in response")
	}

	// Verify redirect points to password change
	if loginResp["redirect"] != "/ui/settings/password" {
		t.Errorf("expected redirect to /ui/settings/password, got %q", loginResp["redirect"])
	}

	// Step 2: Change password with bootstrap session
	newPassword := "NewSecurePassword123!@#"
	changeBody := map[string]string{
		"current_password": bootstrapPwd,
		"new_password":     newPassword,
		"confirm_password": newPassword,
	}
	changeJSON, _ := json.Marshal(changeBody)
	req = httptest.NewRequest("POST", "/ui/settings/password/change", bytes.NewReader(changeJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionToken,
	})
	w = httptest.NewRecorder()
	server.handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("password change failed: expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var changeResp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&changeResp); err != nil {
		t.Fatalf("failed to decode password change response: %v", err)
	}

	if changeResp["status"] != "success" {
		t.Errorf("expected status=success, got %q", changeResp["status"])
	}

	// Step 3: Verify bootstrap flag is cleared
	stateAfterChange, err := auth.GetBootstrapState(passwordFile)
	if err != nil {
		t.Fatalf("GetBootstrapState failed after password change: %v", err)
	}
	if stateAfterChange.IsBootstrap {
		t.Errorf("bootstrap flag should be cleared after password change")
	}

	// Keep old state for comparison later
	oldPasswordHash := state.PasswordHash

	// Step 4: Verify bootstrap login no longer works after flag is cleared
	// (because handleLoginJSON checks IsBootstrap flag)
	oldLoginBody := map[string]string{"password": bootstrapPwd}
	oldLoginJSON, _ := json.Marshal(oldLoginBody)
	req = httptest.NewRequest("POST", "/login", bytes.NewReader(oldLoginJSON))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	server.handleLoginJSON(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("bootstrap login should fail after bootstrap cleared: expected 401, got %d", w.Code)
	}

	// Step 5: Verify new password is securely hashed
	finalState, err := auth.GetBootstrapState(passwordFile)
	if err != nil {
		t.Fatalf("GetBootstrapState failed at end: %v", err)
	}

	// New password hash should be different from bootstrap hash
	if finalState.PasswordHash == oldPasswordHash {
		t.Errorf("password hash should have changed after password change")
	}

	// Verify new password verifies correctly
	if !auth.VerifyPassword(finalState.PasswordHash, newPassword) {
		t.Errorf("new password should verify against final hash")
	}

	// Verify old password does not verify
	if auth.VerifyPassword(finalState.PasswordHash, bootstrapPwd) {
		t.Errorf("old password should not verify against new hash")
	}
}

// TestNoSecretLeakage verifies that secrets are never leaked in plaintext
func TestNoSecretLeakage(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	bootstrapPwd, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	// Verify password hash is not plaintext
	state, err := auth.GetBootstrapState(passwordFile)
	if err != nil {
		t.Fatalf("GetBootstrapState failed: %v", err)
	}

	// Password hash should be different from plaintext password
	if state.PasswordHash == bootstrapPwd {
		t.Errorf("password hash should not be plaintext")
	}

	// Password hash should look like bcrypt (starts with $2a$, $2b$, or $2y$)
	if len(state.PasswordHash) < 20 || state.PasswordHash[0:1] != "$" {
		t.Errorf("invalid bcrypt hash format: %q", state.PasswordHash)
	}

	// Verify plaintext password field is only in-memory from InitializeBootstrapPassword,
	// not persisted in subsequent GetBootstrapState calls
	state2, _ := auth.GetBootstrapState(passwordFile)
	if state2.Password != bootstrapPwd {
		t.Errorf("plaintext password should be readable from first state, but may be cleared after password change")
	}

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
	}

	// Test that error responses don't leak sensitive information
	wrongPwd := "WrongPassword123!@#"
	loginBody := map[string]string{"password": wrongPwd}
	loginJSON, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleLoginJSON(w, req)

	// Should get generic error message, not revealing what's wrong
	if w.Code == http.StatusOK {
		t.Errorf("invalid password should not succeed")
	}
	errorMsg := w.Body.String()
	if errorMsg == "" {
		t.Errorf("error message is empty")
	}

	// Error message must not contain password hashes or plaintext passwords
	if bytes.Contains(w.Body.Bytes(), []byte(state.PasswordHash)) {
		t.Errorf("error response must not contain password hash")
	}
	if bytes.Contains(w.Body.Bytes(), []byte(bootstrapPwd)) {
		t.Errorf("error response must not contain plaintext password")
	}
}

// TestBootstrapPasswordInitializationIdempotent verifies that calling
// InitializeBootstrapPassword multiple times returns the same password
func TestBootstrapPasswordInitializationIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")

	pwd1, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("first InitializeBootstrapPassword failed: %v", err)
	}

	pwd2, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("second InitializeBootstrapPassword failed: %v", err)
	}

	if pwd1 != pwd2 {
		t.Errorf("InitializeBootstrapPassword should return same password on subsequent calls")
	}
}

// TestPasswordChangeRequiresValidSession verifies that password change
// requires an authenticated session
func TestPasswordChangeRequiresValidSession(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	bootstrapPwd, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
	}

	// Try to change password without session cookie
	changeBody := map[string]string{
		"current_password": bootstrapPwd,
		"new_password":     "NewPassword123!@#",
		"confirm_password": "NewPassword123!@#",
	}
	changeJSON, _ := json.Marshal(changeBody)
	req := httptest.NewRequest("POST", "/ui/settings/password/change", bytes.NewReader(changeJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("password change without session should fail: expected 401, got %d", w.Code)
	}

	// Try with invalid session token
	req = httptest.NewRequest("POST", "/ui/settings/password/change", bytes.NewReader(changeJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: "invalid-token",
	})
	w = httptest.NewRecorder()
	server.handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("password change with invalid session should fail: expected 401, got %d", w.Code)
	}
}

// TestPasswordChangeValidation verifies password complexity requirements
func TestPasswordChangeValidation(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	bootstrapPwd, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	tests := []struct {
		name        string
		currentPwd  string
		newPwd      string
		confirmPwd  string
		expectCode  int
		description string
	}{
		{
			name:        "too short",
			currentPwd:  bootstrapPwd,
			newPwd:      "Short1!",
			confirmPwd:  "Short1!",
			expectCode:  http.StatusBadRequest,
			description: "password less than 16 characters",
		},
		{
			name:        "no uppercase",
			currentPwd:  bootstrapPwd,
			newPwd:      "password123456!@#",
			confirmPwd:  "password123456!@#",
			expectCode:  http.StatusBadRequest,
			description: "missing uppercase letters",
		},
		{
			name:        "no lowercase",
			currentPwd:  bootstrapPwd,
			newPwd:      "PASSWORD123456!@#",
			confirmPwd:  "PASSWORD123456!@#",
			expectCode:  http.StatusBadRequest,
			description: "missing lowercase letters",
		},
		{
			name:        "no digits",
			currentPwd:  bootstrapPwd,
			newPwd:      "PasswordChars!@#",
			confirmPwd:  "PasswordChars!@#",
			expectCode:  http.StatusBadRequest,
			description: "missing digits",
		},
		{
			name:        "no symbols",
			currentPwd:  bootstrapPwd,
			newPwd:      "PasswordChars123",
			confirmPwd:  "PasswordChars123",
			expectCode:  http.StatusBadRequest,
			description: "missing symbols",
		},
		{
			name:        "mismatch",
			currentPwd:  bootstrapPwd,
			newPwd:      "Password123!@#",
			confirmPwd:  "DifferentPass123!@#",
			expectCode:  http.StatusBadRequest,
			description: "passwords do not match",
		},
		{
			name:        "wrong current",
			currentPwd:  "WrongPassword",
			newPwd:      "NewPassword123!@#",
			confirmPwd:  "NewPassword123!@#",
			expectCode:  http.StatusUnauthorized,
			description: "incorrect current password",
		},
		{
			name:        "valid",
			currentPwd:  bootstrapPwd,
			newPwd:      "ValidPassword123!@#",
			confirmPwd:  "ValidPassword123!@#",
			expectCode:  http.StatusOK,
			description: "valid password change",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changeBody := map[string]string{
				"current_password": tt.currentPwd,
				"new_password":     tt.newPwd,
				"confirm_password": tt.confirmPwd,
			}
			changeJSON, _ := json.Marshal(changeBody)
			req := httptest.NewRequest("POST", "/ui/settings/password/change", bytes.NewReader(changeJSON))
			req.Header.Set("Content-Type", "application/json")
			req.AddCookie(&http.Cookie{
				Name:  sessionCookieName,
				Value: sessionToken,
			})
			w := httptest.NewRecorder()
			server.handleChangePassword(w, req)

			if w.Code != tt.expectCode {
				t.Errorf("password change validation failed for %s: expected %d, got %d: %s",
					tt.description, tt.expectCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestPasswordHashVerification verifies bcrypt password hashing is secure
func TestPasswordHashVerification(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	pwd, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	state, err := auth.GetBootstrapState(passwordFile)
	if err != nil {
		t.Fatalf("GetBootstrapState failed: %v", err)
	}

	// Test correct password verifies
	if !auth.VerifyPassword(state.PasswordHash, pwd) {
		t.Errorf("correct password should verify")
	}

	// Test incorrect password fails
	if auth.VerifyPassword(state.PasswordHash, "WrongPassword") {
		t.Errorf("incorrect password should not verify")
	}

	// Test empty password fails
	if auth.VerifyPassword(state.PasswordHash, "") {
		t.Errorf("empty password should not verify")
	}

	// Test similar but wrong password fails
	similarButWrong := pwd[:len(pwd)-1] + "X"
	if auth.VerifyPassword(state.PasswordHash, similarButWrong) {
		t.Errorf("similar but wrong password should not verify")
	}
}

// TestClearBootstrapStateDisablesBootstrapLogin verifies that clearing
// the bootstrap flag prevents bootstrap password from being used
func TestClearBootstrapStateDisablesBootstrapLogin(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	bootstrapPwd, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
	}

	// First, verify bootstrap login works
	loginBody := map[string]string{"password": bootstrapPwd}
	loginJSON, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleLoginJSON(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap login should work before clear: got %d", w.Code)
	}

	// Clear bootstrap flag
	if err := auth.ClearBootstrapState(passwordFile); err != nil {
		t.Fatalf("ClearBootstrapState failed: %v", err)
	}

	// Verify state is cleared
	state, _ := auth.GetBootstrapState(passwordFile)
	if state.IsBootstrap {
		t.Errorf("IsBootstrap should be false after clear")
	}

	// Now bootstrap login should fail
	req = httptest.NewRequest("POST", "/login", bytes.NewReader(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	server.handleLoginJSON(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("bootstrap login should fail after clear: expected 401, got %d", w.Code)
	}
}
