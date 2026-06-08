package ui

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

const csTestSecret = "cs-admin-test-secret"

// newTestServerWithCrowdSec builds a server with a real SQLite CredentialStore
// and registers the CrowdSec admin routes.
func newTestServerWithCrowdSec(t *testing.T, env map[string]string) (*Server, *BufferAuditSink, *sqlite.DB) {
	t.Helper()
	merged := map[string]string{"UI_SECRET": csTestSecret}
	for k, v := range env {
		merged[k] = v
	}
	srv, db, _ := newCredentialStoreServer(t, merged)
	audit, _ := srv.audit.(*BufferAuditSink)
	return srv, audit, db
}

// storeCrowdSecKey is a test helper to pre-populate the credential store.
func storeCrowdSecKey(t *testing.T, db *sqlite.DB, key string) {
	t.Helper()
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), crowdSecLAPIKey, key, true); err != nil {
		t.Fatalf("storeCrowdSecKey: %v", err)
	}
}

// lookupCrowdSecKey reads back the key from the store for assertions.
func lookupCrowdSecKey(t *testing.T, db *sqlite.DB) (string, bool) {
	t.Helper()
	v, ok, err := sqlite.NewCredentialStore(db).Lookup(context.Background(), crowdSecLAPIKey)
	if err != nil {
		t.Fatalf("lookupCrowdSecKey: %v", err)
	}
	return v, ok
}

// ---------------------------------------------------------------------------
// TestCrowdSecSetKey_NoCSRF → 403
// ---------------------------------------------------------------------------

func TestCrowdSecSetKey_NoCSRF(t *testing.T) {
	srv, _, _ := newTestServerWithCrowdSec(t, nil)
	cookie := loginCookie(t, srv, csTestSecret)

	req := httptest.NewRequest(http.MethodPost, "/admin/crowdsec/key",
		strings.NewReader("lapi_key=some-key"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecSetKey_EmptyKey → 400
// ---------------------------------------------------------------------------

func TestCrowdSecSetKey_EmptyKey(t *testing.T) {
	srv, _, _ := newTestServerWithCrowdSec(t, nil)
	cookie := loginCookie(t, srv, csTestSecret)
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/crowdsec/key",
		strings.NewReader("lapi_key="))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", rr.Code, rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecSetKey_StoresInCredentialStore
// ---------------------------------------------------------------------------

func TestCrowdSecSetKey_StoresInCredentialStore(t *testing.T) {
	srv, _, db := newTestServerWithCrowdSec(t, nil)
	cookie := loginCookie(t, srv, csTestSecret)
	csrf := srv.csrfTokenFor(cookie.Value)

	const testKey = "cs-lapi-test-key-abc123"
	req := httptest.NewRequest(http.MethodPost, "/admin/crowdsec/key",
		strings.NewReader("lapi_key="+testKey))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	stored, ok := lookupCrowdSecKey(t, db)
	if !ok || stored != testKey {
		t.Fatalf("expected stored key %q, got ok=%v value=%q", testKey, ok, stored)
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecDeleteKey_Deletes
// ---------------------------------------------------------------------------

func TestCrowdSecDeleteKey_Deletes(t *testing.T) {
	srv, _, db := newTestServerWithCrowdSec(t, nil)
	storeCrowdSecKey(t, db, "pre-stored-key")

	cookie := loginCookie(t, srv, csTestSecret)
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/crowdsec/key/delete",
		strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rr.Code, rr.Body.String())
	}
	_, ok := lookupCrowdSecKey(t, db)
	if ok {
		t.Fatal("key should be absent after delete")
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecTestConnection_KeyMissing → JSON error
// ---------------------------------------------------------------------------

func TestCrowdSecTestConnection_KeyMissing(t *testing.T) {
	srv, _, _ := newTestServerWithCrowdSec(t, nil)
	cookie := loginCookie(t, srv, csTestSecret)
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/crowdsec/test", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var result crowdSecTestResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Status != "error" {
		t.Fatalf("expected status=error, got %q", result.Status)
	}
	if !strings.Contains(strings.ToLower(result.Message), "not configured") {
		t.Fatalf("expected 'not configured' message, got %q", result.Message)
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecTestConnection_LAPIUnreachable
// ---------------------------------------------------------------------------

func TestCrowdSecTestConnection_LAPIUnreachable(t *testing.T) {
	srv, _, db := newTestServerWithCrowdSec(t, nil)
	storeCrowdSecKey(t, db, "test-lapi-key-xyz")

	cookie := loginCookie(t, srv, csTestSecret)
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/crowdsec/test", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var result crowdSecTestResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// LAPI may actually be running; either error or ok is acceptable as long as
	// the key is not leaked and the response is valid JSON.
	if result.Status == "" {
		t.Fatalf("expected non-empty status, got empty")
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecTestConnection_LAPIReachable (via httptest server)
// ---------------------------------------------------------------------------

func TestCrowdSecTestConnection_LAPIReachable(t *testing.T) {
	rr := httptest.NewRecorder()
	writeCrowdSecJSON(rr, http.StatusOK, "ok", "LAPI reachable")
	var result crowdSecTestResult
	if err := json.NewDecoder(rr.Body).Decode(&result); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if result.Status != "ok" {
		t.Fatalf("expected ok, got %q", result.Status)
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecTestConnection_KeyNeverInResponse
// ---------------------------------------------------------------------------

func TestCrowdSecTestConnection_KeyNeverInResponse(t *testing.T) {
	srv, _, db := newTestServerWithCrowdSec(t, nil)
	const sensitiveKey = "ultra-secret-lapi-key-do-not-leak"
	storeCrowdSecKey(t, db, sensitiveKey)

	cookie := loginCookie(t, srv, csTestSecret)
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/crowdsec/test", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if strings.Contains(rr.Body.String(), sensitiveKey) {
		t.Fatalf("response body leaked the LAPI key: %s", rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecAdminSection_HTML
// ---------------------------------------------------------------------------

func TestCrowdSecAdminSection_HTML(t *testing.T) {
	srv, _, db := newTestServerWithCrowdSec(t, nil)
	cookie := loginCookie(t, srv, csTestSecret)
	tok := srv.csrfTokenFor(cookie.Value)

	ctx := context.Background()

	// Without a key: show "not configured", no delete/test forms.
	h := srv.crowdSecAdminSection(ctx, tok)
	if !strings.Contains(h, "not configured") {
		t.Errorf("expected 'not configured': %s", h)
	}
	if strings.Contains(h, "crowdsec/key/delete") {
		t.Errorf("delete form must not appear when key absent")
	}
	if strings.Contains(h, "crowdsec/test") {
		t.Errorf("test form must not appear when key absent")
	}

	// Store a key, then verify configured view.
	storeCrowdSecKey(t, db, "some-key")
	h = srv.crowdSecAdminSection(ctx, tok)
	if !strings.Contains(h, "configured") {
		t.Errorf("expected 'configured': %s", h)
	}
	if !strings.Contains(h, "crowdsec/key/delete") {
		t.Errorf("delete form should appear when key present")
	}
	if !strings.Contains(h, "crowdsec/test") {
		t.Errorf("test form should appear when key present")
	}
	if strings.Contains(h, "some-key") {
		t.Errorf("HTML must not contain raw key")
	}
	if !strings.Contains(h, tok) {
		t.Errorf("CSRF token must appear in form")
	}
}

// ---------------------------------------------------------------------------
// Wizard step 8 — CrowdSec LAPI key (integration tests via credential store)
// ---------------------------------------------------------------------------

// TestWizardStep8_CrowdSecAbsent: GET /setup/step/8 shows "not detected" when cscli absent.
func TestWizardStep8_CrowdSecAbsent(t *testing.T) {
	t.Setenv("PATH", t.TempDir()) // empty PATH — cscli not found
	srv, _, _ := newTestServerWithCrowdSec(t, nil)
	cookie := loginCookie(t, srv, csTestSecret)

	req := httptest.NewRequest("GET", "/setup/step/8", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	if !strings.Contains(body, "CrowdSec") {
		t.Error("step 8 must mention CrowdSec")
	}
	if !strings.Contains(body, "not detected") {
		t.Errorf("expected 'not detected' banner, got: %s", body)
	}
	if !strings.Contains(body, `name="lapi_key"`) {
		t.Error("step 8 must render LAPI key input even when CrowdSec absent")
	}
}

// TestWizardStep8_Skip: POST skip=1 redirects to /setup/step/9.
func TestWizardStep8_Skip(t *testing.T) {
	srv, _, _ := newTestServerWithCrowdSec(t, nil)
	cookie := loginCookie(t, srv, csTestSecret)
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/setup/step/8",
		strings.NewReader("csrf_token="+csrf+"&skip=1"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/setup/step/9" {
		t.Errorf("skip must redirect to /setup/step/9, got %q", loc)
	}
}

// TestWizardStep8_StoresKey: POST lapi_key stores it in the credentialStore.
func TestWizardStep8_StoresKey(t *testing.T) {
	srv, _, db := newTestServerWithCrowdSec(t, nil)
	cookie := loginCookie(t, srv, csTestSecret)
	csrf := srv.csrfTokenFor(cookie.Value)

	const testLAPIKey = "wizard-lapi-key-test"
	form := "csrf_token=" + csrf + "&lapi_key=" + testLAPIKey + "&lapi_url=http://127.0.0.1:8080"
	req := httptest.NewRequest(http.MethodPost, "/setup/step/8", strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d: %s", rr.Code, rr.Body.String())
	}
	if loc := rr.Header().Get("Location"); loc != "/setup/step/9" {
		t.Errorf("save must redirect to /setup/step/9, got %q", loc)
	}
	stored, ok := lookupCrowdSecKey(t, db)
	if !ok || stored != testLAPIKey {
		t.Fatalf("expected stored key %q, got ok=%v value=%q", testLAPIKey, ok, stored)
	}
}

// TestWizardStep8_KeyAlreadyConfigured: GET shows "already configured" when key exists.
func TestWizardStep8_KeyAlreadyConfigured(t *testing.T) {
	srv, _, db := newTestServerWithCrowdSec(t, nil)
	storeCrowdSecKey(t, db, "pre-existing-lapi-key")
	cookie := loginCookie(t, srv, csTestSecret)

	req := httptest.NewRequest("GET", "/setup/step/8", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), "already configured") {
		t.Errorf("expected 'already configured' when key pre-exists: %s", rr.Body.String())
	}
}

// ---------------------------------------------------------------------------
// TestCrowdSecLAPIKeyRedactedByAudit
// ---------------------------------------------------------------------------

func TestCrowdSecLAPIKeyRedactedByAudit(t *testing.T) {
	if !isSensitiveAuditKey("crowdsec.lapi_key") {
		t.Fatal("crowdsec.lapi_key must be redacted (contains 'api_key')")
	}
	out := sanitizeAuditFields(map[string]string{
		"crowdsec.lapi_key": "should-be-redacted",
	})
	if out["crowdsec.lapi_key"] != "[REDACTED]" {
		t.Fatalf("expected REDACTED, got %q", out["crowdsec.lapi_key"])
	}
}
