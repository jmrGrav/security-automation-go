package ui

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestForcePasswordChangeMiddleware_RedirectsWhenNoHash verifies that the
// force-password-change middleware redirects to /ui/settings/password/change
// when no admin_password_hash is set in the store (bootstrap active).
func TestForcePasswordChangeMiddleware_RedirectsWhenNoHash(t *testing.T) {
	// Empty store = bootstrap active (no hash set)
	store := newTestAdminStore("")
	server := newServerWithStore(store)

	// Seed a valid session so the session check passes
	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()

	// Wrap a passthrough handler with forcePasswordChangeMiddleware
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server.forcePasswordChangeMiddleware(inner).ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 redirect when bootstrap active, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/ui/settings/password/change" {
		t.Errorf("expected redirect to /ui/settings/password/change, got %q", loc)
	}
}

// TestForcePasswordChangeMiddleware_AllowsWhenHashSet verifies that the
// middleware does NOT redirect when a password hash is already set.
func TestForcePasswordChangeMiddleware_AllowsWhenHashSet(t *testing.T) {
	_, store := seedAdminHash(t, "SecurePassword123!@#")
	server := newServerWithStore(store)

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server.forcePasswordChangeMiddleware(inner).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when hash set, got %d (redirect to %q)", w.Code, w.Header().Get("Location"))
	}
}

// TestForcePasswordChangeMiddleware_AllowsPasswordChangePath verifies that
// the /ui/settings/password/change path is always allowed through, even in
// bootstrap mode — this prevents an infinite redirect loop.
func TestForcePasswordChangeMiddleware_AllowsPasswordChangePath(t *testing.T) {
	// Empty store = bootstrap active
	store := newTestAdminStore("")
	server := newServerWithStore(store)

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	req := httptest.NewRequest("POST", "/ui/settings/password/change", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server.forcePasswordChangeMiddleware(inner).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for /ui/settings/password/change (no loop), got %d", w.Code)
	}
}

// TestForcePasswordChangeMiddleware_NilStoreNoRedirect verifies that nil
// setupStore (legacy install) is treated as "not bootstrap" — no redirect.
func TestForcePasswordChangeMiddleware_NilStoreNoRedirect(t *testing.T) {
	server := newServerWithStore(nil)

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	server.forcePasswordChangeMiddleware(inner).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for nil store (no redirect), got %d", w.Code)
	}
}

// TestIsBootstrapActive verifies the bootstrap state logic.
func TestIsBootstrapActive(t *testing.T) {
	t.Run("nil store", func(t *testing.T) {
		server := newServerWithStore(nil)
		if server.isBootstrapActive() {
			t.Error("nil store should not be bootstrap active")
		}
	})

	t.Run("empty store (no hash)", func(t *testing.T) {
		server := newServerWithStore(newTestAdminStore(""))
		if !server.isBootstrapActive() {
			t.Error("store with no hash should be bootstrap active")
		}
	})

	t.Run("store with hash", func(t *testing.T) {
		_, store := seedAdminHash(t, "SecurePassword123!@#")
		server := newServerWithStore(store)
		if server.isBootstrapActive() {
			t.Error("store with hash should not be bootstrap active")
		}
	})
}
