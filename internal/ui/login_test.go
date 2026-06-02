package ui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/ui/auth"
)

func TestLoginHandler_ValidCredentials(t *testing.T) {
	// Setup server with bootstrap password
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	pwd, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	// Create server with admin password file configured
	t.Setenv("UI_ENABLED", "1")
	t.Setenv("UI_ADDR", "127.0.0.1:9090")
	t.Setenv("UI_SECRET_FILE", filepath.Join(tmpDir, "ui-secrets.local"))
	t.Setenv("UI_PROVIDER_STATE_FILE", filepath.Join(tmpDir, "ai-providers.env"))
	t.Setenv("UI_ADMIN_PASSWORD_FILE", passwordFile)
	t.Setenv("STATE_DIR", tmpDir)
	t.Setenv("CF_API_TOKEN", "test-token")
	t.Setenv("CF_ZONE_ID", "test-zone")

	srv, _, _ := newTestServer(t, nil)

	body := `{"password": "` + pwd + `"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
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
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	_, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	// Create server with admin password file configured
	t.Setenv("UI_ENABLED", "1")
	t.Setenv("UI_ADDR", "127.0.0.1:9090")
	t.Setenv("UI_SECRET_FILE", filepath.Join(tmpDir, "ui-secrets.local"))
	t.Setenv("UI_PROVIDER_STATE_FILE", filepath.Join(tmpDir, "ai-providers.env"))
	t.Setenv("UI_ADMIN_PASSWORD_FILE", passwordFile)
	t.Setenv("STATE_DIR", tmpDir)
	t.Setenv("CF_API_TOKEN", "test-token")
	t.Setenv("CF_ZONE_ID", "test-zone")

	srv, _, _ := newTestServer(t, nil)

	body := `{"password": "wrong-password"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestLoginHandler_BootstrapNotActive(t *testing.T) {
	tmpDir := t.TempDir()
	passwordFile := filepath.Join(tmpDir, "admin_password")
	pwd, err := auth.InitializeBootstrapPassword(passwordFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}

	// Clear bootstrap flag
	if err := auth.ClearBootstrapState(passwordFile); err != nil {
		t.Fatalf("ClearBootstrapState failed: %v", err)
	}

	// Create server with admin password file configured
	t.Setenv("UI_ENABLED", "1")
	t.Setenv("UI_ADDR", "127.0.0.1:9090")
	t.Setenv("UI_SECRET_FILE", filepath.Join(tmpDir, "ui-secrets.local"))
	t.Setenv("UI_PROVIDER_STATE_FILE", filepath.Join(tmpDir, "ai-providers.env"))
	t.Setenv("UI_ADMIN_PASSWORD_FILE", passwordFile)
	t.Setenv("STATE_DIR", tmpDir)
	t.Setenv("CF_API_TOKEN", "test-token")
	t.Setenv("CF_ZONE_ID", "test-zone")

	srv, _, _ := newTestServer(t, nil)

	body := `{"password": "` + pwd + `"}`
	req := httptest.NewRequest("POST", "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 after bootstrap cleared, got %d", w.Code)
	}
}
