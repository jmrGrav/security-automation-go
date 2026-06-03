package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/ui/auth"
)

// initTestBootstrap initializes a bootstrap password and returns the password and error.
func initTestBootstrap(passwordFile string) (string, error) {
	return auth.InitializeBootstrapPassword(passwordFile)
}

// getTestBootstrapState retrieves the current bootstrap state.
func getTestBootstrapState(passwordFile string) (auth.BootstrapState, error) {
	return auth.GetBootstrapState(passwordFile)
}

// testConfig creates a minimal config for testing.
func testConfig(passwordFile string) *config.Config {
	return &config.Config{
		UI: config.UIBoolConfig{
			AdminPasswordFile: passwordFile,
		},
	}
}

func TestChangePassword_ValidFlow(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	// Create valid session
	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	body := `{
		"current_password": "` + oldPwd + `",
		"new_password": "NewPassword123!@#SecurePassword",
		"confirm_password": "NewPassword123!@#SecurePassword"
	}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{
		Name:  sessionCookieName,
		Value: sessionToken,
	})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify bootstrap state is cleared
	state, _ := getTestBootstrapState(passwordFile)
	if state.IsBootstrap {
		t.Errorf("bootstrap flag not cleared after password change")
	}
}

func TestChangePassword_MismatchedPasswords(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	body := `{
		"current_password": "` + oldPwd + `",
		"new_password": "NewPassword123!@#",
		"confirm_password": "DifferentPassword"
	}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for mismatched passwords, got %d", w.Code)
	}
}

func TestChangePassword_WeakPassword(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	body := `{
		"current_password": "` + oldPwd + `",
		"new_password": "weak",
		"confirm_password": "weak"
	}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for weak password, got %d", w.Code)
	}
}

func TestChangePassword_NoSession(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
	}

	body := `{
		"current_password": "` + oldPwd + `",
		"new_password": "NewPassword123!@#",
		"confirm_password": "NewPassword123!@#"
	}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing session, got %d", w.Code)
	}
}

func TestChangePassword_IncorrectCurrentPassword(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	_, _ = initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	body := `{
		"current_password": "WrongPassword",
		"new_password": "NewPassword123!@#",
		"confirm_password": "NewPassword123!@#"
	}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for incorrect current password, got %d", w.Code)
	}
}

func TestChangePassword_PasswordTooShort(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	// 15 chars, need 16
	body := `{
		"current_password": "` + oldPwd + `",
		"new_password": "Short1!Pass1234",
		"confirm_password": "Short1!Pass1234"
	}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for password too short, got %d", w.Code)
	}
}

func TestChangePassword_MissingComplexity(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	// Missing symbol
	body := `{
		"current_password": "` + oldPwd + `",
		"new_password": "NoSymbolPassword123456",
		"confirm_password": "NoSymbolPassword123456"
	}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for missing complexity, got %d", w.Code)
	}
}

func TestChangePassword_InvalidJSON(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	_, _ = initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader("not json"))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400 for invalid JSON, got %d", w.Code)
	}
}

func TestChangePassword_MethodNotAllowed(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	_, _ = initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
	}

	req := httptest.NewRequest("GET", "/ui/settings/password/change", nil)
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestChangePassword_ValidResponseFormat(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	body := `{
		"current_password": "` + oldPwd + `",
		"new_password": "ValidPassword123!@#",
		"confirm_password": "ValidPassword123!@#"
	}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}

	var resp map[string]string
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("failed to decode response: %v", err)
	}

	if resp["status"] != "success" {
		t.Errorf("expected status='success', got %q", resp["status"])
	}

	if resp["redirect"] != "/ui/dashboard" {
		t.Errorf("expected redirect='/ui/dashboard', got %q", resp["redirect"])
	}
}

func TestHasPasswordComplexity(t *testing.T) {
	tests := []struct {
		password string
		want     bool
	}{
		{"ValidPass123!@#", true},
		{"AnotherGood1234!", true},
		{"NoSymbolPassword123", false},
		{"nosymbols123!@#", false},
		{"NOSYMBOLS123!@#", false},
		{"NoDigits!@#Pass", false},
		{"123456!@#Pass", true},
		{"a", false},
		{"", false},
	}

	for _, tc := range tests {
		t.Run(tc.password, func(t *testing.T) {
			got := hasPasswordComplexity(tc.password)
			if got != tc.want {
				t.Errorf("hasPasswordComplexity(%q) = %v, want %v", tc.password, got, tc.want)
			}
		})
	}
}

func TestChangePassword_MissingCSRF(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	body := `{"current_password":"` + oldPwd + `","new_password":"NewPassword123!@#Secure","confirm_password":"NewPassword123!@#Secure"}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	// No X-CSRF-Token header
	w := httptest.NewRecorder()
	server.handleChangePassword(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for missing CSRF, got %d", w.Code)
	}
}

func TestChangePassword_InvalidCSRF(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	body := `{"current_password":"` + oldPwd + `","new_password":"NewPassword123!@#Secure","confirm_password":"NewPassword123!@#Secure"}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", "wrong-token")
	w := httptest.NewRecorder()
	server.handleChangePassword(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 for invalid CSRF, got %d", w.Code)
	}
}

// TestChangePassword_ValidCSRF verifies that a correct X-CSRF-Token header
// is accepted and the request proceeds. It does not test the full flow —
// see TestChangePassword_ValidFlow for that.
func TestChangePassword_ValidCSRF(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	oldPwd, _ := initTestBootstrap(passwordFile)

	server := &Server{
		cfg:      testConfig(passwordFile),
		sessions: make(map[string]time.Time),
		uiSecret: "test-secret",
	}

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	body := `{"current_password":"` + oldPwd + `","new_password":"NewPassword123!@#Secure","confirm_password":"NewPassword123!@#Secure"}`
	req := httptest.NewRequest("POST", "/ui/settings/password/change", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", server.csrfTokenFor(sessionToken))
	w := httptest.NewRecorder()
	server.handleChangePassword(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for valid CSRF, got %d: %s", w.Code, w.Body.String())
	}
}
