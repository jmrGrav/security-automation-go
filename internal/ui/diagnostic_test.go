package ui

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestHandleRunDiagnostic_MethodNotAllowed(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)
	req := httptest.NewRequest("GET", "/health/diagnostic", nil)
	w := httptest.NewRecorder()
	srv.handleRunDiagnostic(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", w.Code)
	}
}

func TestHandleRunDiagnostic_NoSession(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)
	req := httptest.NewRequest("POST", "/health/diagnostic", nil)
	w := httptest.NewRecorder()
	srv.handleRunDiagnostic(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401, got %d", w.Code)
	}
}

func TestHandleRunDiagnostic_InvalidCSRF(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)

	sessionToken := generateSessionToken()
	srv.mu.Lock()
	srv.sessions[sessionToken] = time.Now().Add(sessionTTL)
	srv.mu.Unlock()

	req := httptest.NewRequest("POST", "/health/diagnostic", strings.NewReader("csrf_token=wrong"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()
	srv.handleRunDiagnostic(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403, got %d", w.Code)
	}
}

func TestHandleRunDiagnostic_ValidRequest(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)
	srv.cfg.StateDir = t.TempDir()

	sessionToken := generateSessionToken()
	srv.mu.Lock()
	srv.sessions[sessionToken] = time.Now().Add(sessionTTL)
	srv.mu.Unlock()

	csrfToken := srv.csrfTokenFor(sessionToken)
	req := httptest.NewRequest("POST", "/health/diagnostic",
		strings.NewReader("csrf_token="+csrfToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	w := httptest.NewRecorder()
	srv.handleRunDiagnostic(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/json") {
		t.Errorf("expected JSON content type, got %q", ct)
	}
	var report map[string]any
	if err := json.NewDecoder(w.Body).Decode(&report); err != nil {
		t.Fatalf("cannot decode response: %v", err)
	}
	for _, key := range []string{"generated_at", "health", "detection", "runtime_info"} {
		if _, ok := report[key]; !ok {
			t.Errorf("expected key %q in response", key)
		}
	}
}

func TestHandleSupportBundle_Returns200WithGzip(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)
	srv.cfg.StateDir = t.TempDir()

	sessionToken := generateSessionToken()
	srv.mu.Lock()
	srv.sessions[sessionToken] = time.Now().Add(sessionTTL)
	srv.mu.Unlock()

	req := httptest.NewRequest("GET", "/health/support-bundle", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()
	srv.handleSupportBundle(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	ct := w.Header().Get("Content-Type")
	if !strings.Contains(ct, "gzip") {
		t.Errorf("expected gzip content type, got %q", ct)
	}
	cd := w.Header().Get("Content-Disposition")
	if !strings.Contains(cd, "support-bundle") {
		t.Errorf("expected support-bundle in Content-Disposition, got %q", cd)
	}
}

func TestHandleSupportBundle_NoSession_Returns401(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)

	req := httptest.NewRequest("GET", "/health/support-bundle", nil)
	// no session cookie
	w := httptest.NewRecorder()
	srv.handleSupportBundle(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for missing session, got %d", w.Code)
	}
}

func TestHandleSupportBundle_ExcludesSecretMaterial(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "cloudflare.api_token", "bundle-secret-token", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/health/support-bundle", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("bundle-secret-token")) {
		t.Fatalf("support bundle leaked credential material")
	}
	gr, err := gzip.NewReader(bytes.NewReader(rr.Body.Bytes()))
	if err != nil {
		t.Fatalf("gzip reader: %v", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	for {
		hdr, err := tr.Next()
		if err != nil {
			break
		}
		if strings.Contains(hdr.Name, "secret.key") || strings.Contains(hdr.Name, "runtime.db") {
			t.Fatalf("support bundle included forbidden entry %q", hdr.Name)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read tar entry %s: %v", hdr.Name, err)
		}
		if bytes.Contains(data, []byte("bundle-secret-token")) {
			t.Fatalf("support bundle entry %q leaked credential material", hdr.Name)
		}
	}
}

func TestRedactSecretLines(t *testing.T) {
	tests := []struct {
		input    string
		contains string
		absent   string
	}{
		{
			input:    "token=abc123secret",
			contains: "<REDACTED>",
			absent:   "abc123secret",
		},
		{
			input:    "api_key: supersecretvalue",
			contains: "<REDACTED>",
			absent:   "supersecretvalue",
		},
		{
			input:    "normal log line",
			contains: "normal log line",
			absent:   "<REDACTED>",
		},
		{
			input:    "PASSWORD=hunter2",
			contains: "<REDACTED>",
			absent:   "hunter2",
		},
	}
	for _, tc := range tests {
		result := redactSecretLines(tc.input)
		if !strings.Contains(result, tc.contains) {
			t.Errorf("expected %q to contain %q, got %q", tc.input, tc.contains, result)
		}
		if tc.absent != "" && strings.Contains(result, tc.absent) {
			t.Errorf("expected %q NOT to contain %q, got %q", tc.input, tc.absent, result)
		}
	}
}

func TestDiagnosticReport_StoredToDisk(t *testing.T) {
	_, store := seedAdminHash(t, "Password123!@#")
	srv := newServerWithStore(store)
	stateDir := t.TempDir()
	srv.cfg.StateDir = stateDir

	sessionToken := generateSessionToken()
	srv.mu.Lock()
	srv.sessions[sessionToken] = time.Now().Add(sessionTTL)
	srv.mu.Unlock()

	csrfToken := srv.csrfTokenFor(sessionToken)
	req := httptest.NewRequest("POST", "/health/diagnostic",
		strings.NewReader("csrf_token="+csrfToken))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	req.Header.Set("X-CSRF-Token", csrfToken)
	w := httptest.NewRecorder()
	srv.handleRunDiagnostic(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}

	// Verify a file was created in diagnostics/
	entries, err := os.ReadDir(stateDir + "/diagnostics")
	if err != nil {
		t.Fatalf("diagnostics dir not created: %v", err)
	}
	if len(entries) != 1 {
		t.Errorf("expected 1 diagnostic file, found %d", len(entries))
	}
	if !strings.HasSuffix(entries[0].Name(), ".json") {
		t.Errorf("expected .json file, got %q", entries[0].Name())
	}
}

func TestHandleRunDiagnostic_DoesNotLeakCredentialValues(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{"UI_SECRET": "ui-secret-value"})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "cloudflare.api_token", "diagnostic-secret-token", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest("POST", "/health/diagnostic",
		strings.NewReader("csrf_token="+srv.csrfTokenFor(cookie.Value)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if bytes.Contains(rr.Body.Bytes(), []byte("diagnostic-secret-token")) {
		t.Fatalf("diagnostic report leaked credential material")
	}
}
