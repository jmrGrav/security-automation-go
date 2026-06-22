package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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

// TestLoginHandler_JSONPrunesExpiredSessions guards parity between the JSON
// and form login paths: both must sweep expired/over-limit sessions on every
// successful login, not just the form path. Without this, the JSON login
// endpoint lets the in-memory session map grow without bound.
func TestLoginHandler_JSONPrunesExpiredSessions(t *testing.T) {
	pwd, store := seedAdminHash(t, "TestPassword123!@#Secure")
	server := newServerWithStore(store)

	server.mu.Lock()
	server.sessionMax = 1
	server.sessions["expired-1"] = time.Now().Add(-time.Hour)
	server.sessions["expired-2"] = time.Now().Add(-time.Hour)
	server.mu.Unlock()

	body := `{"password": "` + pwd + `"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleLoginJSON(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	server.mu.Lock()
	count := len(server.sessions)
	server.mu.Unlock()

	if count > server.sessionMax {
		t.Fatalf("expected session map pruned to sessionMax=%d after JSON login, got %d entries", server.sessionMax, count)
	}
	if _, ok := server.sessions["expired-1"]; ok {
		t.Fatalf("expired session was not pruned on JSON login")
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
