package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLoginHandler_ValidCredentials(t *testing.T) {
	pwd, store := seedAdminHash(t, "TestPassword123!@#Secure")
	server := newServerWithStore(store)

	body := `{"password": "` + pwd + `"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLoginJSON(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Errorf("failed to decode response: %v", err)
	}

	if _, ok := resp["session_token"]; !ok {
		t.Errorf("response missing session_token")
	}
}

func TestLoginHandler_InvalidCredentials(t *testing.T) {
	_, store := seedAdminHash(t, "TestPassword123!@#Secure")
	server := newServerWithStore(store)

	body := `{"password": "wrong-password"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLoginJSON(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLoginHandler_NoHashInStore(t *testing.T) {
	// Empty store — no admin_password_hash set (setup not complete)
	store := newTestAdminStore("")
	server := newServerWithStore(store)

	body := `{"password": "AnyPassword123!@#"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLoginJSON(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when no hash stored, got %d", w.Code)
	}
}

func TestLoginHandler_NoSetupStore(t *testing.T) {
	// No setup store at all → 503
	server := newServerWithStore(nil)

	body := `{"password": "AnyPassword123!@#"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLoginJSON(w, req)

	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 when setupStore is nil, got %d", w.Code)
	}
}
