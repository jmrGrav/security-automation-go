package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/ui/auth"
)

// TestFullAuthenticationFlow verifies the complete authentication lifecycle:
// 1. Seed admin hash into SQLite store
// 2. Login with the known password → 200 + session token
// 3. Change password with valid session
// 4. Verify new hash is stored; old password no longer verifies
func TestFullAuthenticationFlow(t *testing.T) {
	initialPwd := "InitialPass123!@#Secure"
	_, store := seedAdminHash(t, initialPwd)

	server := newServerWithStore(store)
	server.uiSecret = "test-secret"

	// Step 1: Login with initial password via JSON
	loginBody := map[string]string{"password": initialPwd}
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

	// After normal login, redirect is to root (not password change page)
	if loginResp["redirect"] == "" {
		t.Errorf("expected a redirect in response, got empty")
	}

	// Step 2: Change password with valid session
	newPassword := "NewSecurePassword123!@#"
	changeBody := map[string]string{
		"current_password": initialPwd,
		"new_password":     newPassword,
		"confirm_password": newPassword,
	}
	changeJSON, _ := json.Marshal(changeBody)
	req = httptest.NewRequest("POST", "/ui/settings/password/change", bytes.NewReader(changeJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
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

	// Step 3: Verify hash changed — old password no longer works
	newHash, _, _ := store.GetSetting(context.Background(), "admin_password_hash")
	if auth.VerifyPassword(newHash, initialPwd) {
		t.Errorf("old password should not verify against new hash")
	}
	if !auth.VerifyPassword(newHash, newPassword) {
		t.Errorf("new password should verify against stored hash")
	}
}

// TestNoSecretLeakage verifies that wrong passwords give 401 and responses
// never contain the password hash or plaintext.
func TestNoSecretLeakage(t *testing.T) {
	initialPwd := "SecretPassword123!@#"
	_, store := seedAdminHash(t, initialPwd)

	hash, _, _ := store.GetSetting(context.Background(), "admin_password_hash")

	server := newServerWithStore(store)

	// Wrong password attempt
	wrongPwd := "WrongPassword123!@#"
	loginBody := map[string]string{"password": wrongPwd}
	loginJSON, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleLoginJSON(w, req)

	if w.Code == http.StatusOK {
		t.Errorf("invalid password should not succeed")
	}

	body := w.Body.Bytes()
	// Error response must not contain the bcrypt hash or plaintext passwords
	if bytes.Contains(body, []byte(hash)) {
		t.Errorf("error response must not contain password hash")
	}
	if bytes.Contains(body, []byte(initialPwd)) {
		t.Errorf("error response must not contain plaintext initial password")
	}
	if bytes.Contains(body, []byte(wrongPwd)) {
		t.Errorf("error response must not contain attempted password")
	}
}

// TestInitialPasswordFileIdempotent verifies that calling GenerateInitialPassword
// multiple times returns the same password without overwriting the file.
func TestInitialPasswordFileIdempotent(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "runtime", "initial-admin-password")

	pwd1, err := auth.GenerateInitialPassword(passwordFile)
	if err != nil {
		t.Fatalf("first GenerateInitialPassword failed: %v", err)
	}

	pwd2, err := auth.GenerateInitialPassword(passwordFile)
	if err != nil {
		t.Fatalf("second GenerateInitialPassword failed: %v", err)
	}

	if pwd1 != pwd2 {
		t.Errorf("GenerateInitialPassword should return same password on subsequent calls")
	}
}

// TestPasswordChangeRequiresValidSession verifies that password change
// requires an authenticated session.
func TestPasswordChangeRequiresValidSession(t *testing.T) {
	_, store := seedAdminHash(t, "SomePassword123!@#")

	server := newServerWithStore(store)

	changeBody := map[string]string{
		"current_password": "SomePassword123!@#",
		"new_password":     "NewPassword123!@#",
		"confirm_password": "NewPassword123!@#",
	}
	changeJSON, _ := json.Marshal(changeBody)

	// No session cookie
	req := httptest.NewRequest("POST", "/ui/settings/password/change", bytes.NewReader(changeJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("password change without session should fail: expected 401, got %d", w.Code)
	}

	// Invalid session token
	req = httptest.NewRequest("POST", "/ui/settings/password/change", bytes.NewReader(changeJSON))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: "invalid-token"})
	w = httptest.NewRecorder()
	server.handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("password change with invalid session should fail: expected 401, got %d", w.Code)
	}
}

// TestPasswordChangeValidation verifies password complexity requirements.
func TestPasswordChangeValidation(t *testing.T) {
	bootstrapPwd := "BootstrapPassword123!@#"
	_, store := seedAdminHash(t, bootstrapPwd)

	server := newServerWithStore(store)
	server.uiSecret = "test-secret"

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	tests := []struct {
		name       string
		currentPwd string
		newPwd     string
		confirmPwd string
		expectCode int
		desc       string
	}{
		{
			name: "too short", currentPwd: bootstrapPwd,
			newPwd: "Short1!", confirmPwd: "Short1!",
			expectCode: http.StatusBadRequest, desc: "password less than 16 chars",
		},
		{
			name: "no uppercase", currentPwd: bootstrapPwd,
			newPwd: "password123456!@#", confirmPwd: "password123456!@#",
			expectCode: http.StatusBadRequest, desc: "missing uppercase",
		},
		{
			name: "no lowercase", currentPwd: bootstrapPwd,
			newPwd: "PASSWORD123456!@#", confirmPwd: "PASSWORD123456!@#",
			expectCode: http.StatusBadRequest, desc: "missing lowercase",
		},
		{
			name: "no digits", currentPwd: bootstrapPwd,
			newPwd: "PasswordChars!@#", confirmPwd: "PasswordChars!@#",
			expectCode: http.StatusBadRequest, desc: "missing digits",
		},
		{
			name: "no symbols", currentPwd: bootstrapPwd,
			newPwd: "PasswordChars123", confirmPwd: "PasswordChars123",
			expectCode: http.StatusBadRequest, desc: "missing symbols",
		},
		{
			name: "mismatch", currentPwd: bootstrapPwd,
			newPwd: "Password123!@#", confirmPwd: "DifferentPass123!@#",
			expectCode: http.StatusBadRequest, desc: "passwords do not match",
		},
		{
			name: "wrong current", currentPwd: "WrongPassword",
			newPwd: "NewPassword123!@#", confirmPwd: "NewPassword123!@#",
			expectCode: http.StatusUnauthorized, desc: "incorrect current password",
		},
		{
			name: "valid", currentPwd: bootstrapPwd,
			newPwd: "ValidPassword123!@#", confirmPwd: "ValidPassword123!@#",
			expectCode: http.StatusOK, desc: "valid password change",
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
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
			req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
			w := httptest.NewRecorder()
			server.handleChangePassword(w, req)

			if w.Code != tt.expectCode {
				t.Errorf("%s: expected %d, got %d: %s", tt.desc, tt.expectCode, w.Code, w.Body.String())
			}
		})
	}
}

// TestPasswordHashVerification verifies bcrypt password hashing is secure.
func TestPasswordHashVerification(t *testing.T) {
	pwd := "TestPassword123!@#"
	hash, err := auth.HashPassword(pwd)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	// Hash must not be plaintext
	if hash == pwd {
		t.Errorf("hash must not equal plaintext password")
	}

	// Must look like bcrypt
	if len(hash) < 20 || hash[0] != '$' {
		t.Errorf("invalid bcrypt hash format: %q", hash)
	}

	// Correct password verifies
	if !auth.VerifyPassword(hash, pwd) {
		t.Errorf("correct password should verify")
	}

	// Wrong password fails
	if auth.VerifyPassword(hash, "WrongPassword") {
		t.Errorf("incorrect password should not verify")
	}

	// Empty password fails
	if auth.VerifyPassword(hash, "") {
		t.Errorf("empty password should not verify")
	}

	// Similar but wrong fails
	similar := pwd[:len(pwd)-1] + "X"
	if auth.VerifyPassword(hash, similar) {
		t.Errorf("similar but wrong password should not verify")
	}
}

// TestLoginFailsWithNoHash verifies that login fails when no admin_password_hash
// exists in the store (bootstrap not complete / no password set).
func TestLoginFailsWithNoHash(t *testing.T) {
	// Store with no hash set
	emptyStore := newTestAdminStore("")
	server := newServerWithStore(emptyStore)

	loginBody := map[string]string{"password": "AnyPassword123!@#"}
	loginJSON, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleLoginJSON(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("login with no stored hash should return 401, got %d", w.Code)
	}
}

// TestLoginSucceedsAfterHashSet verifies that login works once admin_password_hash
// is set in the store.
func TestLoginSucceedsAfterHashSet(t *testing.T) {
	pwd := "StoredPassword123!@#"
	_, store := seedAdminHash(t, pwd)
	server := newServerWithStore(store)

	loginBody := map[string]string{"password": pwd}
	loginJSON, _ := json.Marshal(loginBody)
	req := httptest.NewRequest("POST", "/login", bytes.NewReader(loginJSON))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleLoginJSON(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("login with valid hash should return 200, got %d: %s", w.Code, w.Body.String())
	}
}
