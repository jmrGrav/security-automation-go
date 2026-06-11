package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/ui/auth"
)

// testAdminStore is a minimal in-memory SetupStorer for tests.
type testAdminStore struct {
	settings map[string]string
	step     int
	complete bool
}

func newTestAdminStore(passwordHash string) *testAdminStore {
	s := &testAdminStore{settings: make(map[string]string), step: 9, complete: true}
	if passwordHash != "" {
		s.settings["admin_password_hash"] = passwordHash
	}
	return s
}

func (s *testAdminStore) GetCurrentStep(_ context.Context) (int, error) { return s.step, nil }
func (s *testAdminStore) SetCurrentStep(_ context.Context, v int) error { s.step = v; return nil }
func (s *testAdminStore) IsComplete(_ context.Context) (bool, error)    { return s.complete, nil }
func (s *testAdminStore) MarkComplete(_ context.Context) error          { s.complete = true; return nil }
func (s *testAdminStore) GetSetting(_ context.Context, k string) (string, bool, error) {
	v, ok := s.settings[k]
	return v, ok, nil
}
func (s *testAdminStore) SetSetting(_ context.Context, k, v string) error {
	s.settings[k] = v
	return nil
}
func (s *testAdminStore) GetAuthEpoch(_ context.Context) (int64, error)       { return 0, nil }
func (s *testAdminStore) IncrementAuthEpoch(_ context.Context) (int64, error) { return 1, nil }
func (s *testAdminStore) GetPasswordChangeRequired(_ context.Context) (bool, error) {
	return false, nil
}
func (s *testAdminStore) SetPasswordChangeRequired(_ context.Context, _ bool) error { return nil }

// seedAdminHash creates a testAdminStore with a low-cost bcrypt hash for speed in tests.
// Production code uses cost 12; tests use bcrypt.MinCost (4) to avoid multi-second delays
// per test, especially under the race detector.
func seedAdminHash(t *testing.T, password string) (string, *testAdminStore) {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("auth.HashPassword: %v", err)
	}
	return password, newTestAdminStore(hash)
}

// seedAdminHashReal uses the production bcrypt cost (12). Use only in tests that
// specifically need to validate the hash cost or are not run under -race.
func seedAdminHashReal(t *testing.T, password string) (string, *testAdminStore) {
	t.Helper()
	hash, err := auth.HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return password, newTestAdminStore(hash)
}

func newServerWithStore(store SetupStorer) *Server {
	return &Server{
		cfg:        config.DefaultConfig(),
		sessions:   make(map[string]time.Time),
		uiSecret:   "test-secret",
		setupStore: store,
	}
}

func TestChangePassword_ValidFlow(t *testing.T) {
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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

	// Verify new hash is stored and old password no longer works
	newHash, _, _ := store.GetSetting(context.Background(), "admin_password_hash")
	if auth.VerifyPassword(newHash, oldPwd) {
		t.Error("old password should not verify against new hash")
	}
	if !auth.VerifyPassword(newHash, "NewPassword123!@#SecurePassword") {
		t.Error("new password should verify against stored hash")
	}
}

func TestChangePassword_MismatchedPasswords(t *testing.T) {
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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
	_, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)
	server.uiSecret = ""

	body := `{
		"current_password": "OldPassword123!@#Secure",
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
	_, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

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
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

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
	_, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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
	_, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

	req := httptest.NewRequest("GET", "/ui/settings/password/change", nil)
	w := httptest.NewRecorder()

	server.handleChangePassword(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405 for GET, got %d", w.Code)
	}
}

func TestChangePassword_ValidResponseFormat(t *testing.T) {
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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

	if resp["redirect"] != "/login" {
		t.Errorf("expected redirect='/login', got %q", resp["redirect"])
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
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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

func TestChangePassword_ValidCSRF(t *testing.T) {
	oldPwd, store := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(store)

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
