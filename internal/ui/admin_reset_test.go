package ui

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// testAdminStoreWithEpoch extends testAdminStore with epoch tracking for
// admin reset / recovery tests.
type testAdminStoreWithEpoch struct {
	testAdminStore
	epoch            int64
	passwordRequired bool
}

func (s *testAdminStoreWithEpoch) GetAuthEpoch(_ context.Context) (int64, error) { return s.epoch, nil }
func (s *testAdminStoreWithEpoch) IncrementAuthEpoch(_ context.Context) (int64, error) {
	s.epoch++
	return s.epoch, nil
}
func (s *testAdminStoreWithEpoch) GetPasswordChangeRequired(_ context.Context) (bool, error) {
	return s.passwordRequired, nil
}
func (s *testAdminStoreWithEpoch) SetPasswordChangeRequired(_ context.Context, v bool) error {
	s.passwordRequired = v
	return nil
}

func TestForcePasswordChangeMiddleware_RedirectsOnPasswordChangeRequired(t *testing.T) {
	_, base := seedAdminHash(t, "OldPassword123!@#Secure")
	store := &testAdminStoreWithEpoch{testAdminStore: *base, passwordRequired: true}
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

	if w.Code != http.StatusFound {
		t.Errorf("expected 302 when password_change_required=true, got %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "/ui/settings/password/change" {
		t.Errorf("expected redirect to /ui/settings/password/change, got %q", loc)
	}
}

func TestForcePasswordChangeMiddleware_NoRedirectWhenFlagClear(t *testing.T) {
	_, base := seedAdminHash(t, "OldPassword123!@#Secure")
	store := &testAdminStoreWithEpoch{testAdminStore: *base, passwordRequired: false}
	server := newServerWithStore(store)

	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	w := httptest.NewRecorder()

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	server.forcePasswordChangeMiddleware(inner).ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200 when flag clear, got %d", w.Code)
	}
}

func TestGetSession_EpochInvalidatesExistingSessions(t *testing.T) {
	_, base := seedAdminHash(t, "OldPassword123!@#Secure")
	store := &testAdminStoreWithEpoch{testAdminStore: *base, epoch: 0}
	server := newServerWithStore(store)

	// Seed a session
	sessionToken := generateSessionToken()
	server.mu.Lock()
	server.sessions[sessionToken] = time.Now().Add(sessionTTL)
	server.mu.Unlock()

	// Session valid at epoch 0
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	if _, ok := server.getSession(req); !ok {
		t.Fatal("expected session valid at epoch 0")
	}

	// CLI reset: epoch bumped to 1 in DB
	store.epoch = 1

	// Same session now invalid
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	if _, ok := server.getSession(req2); ok {
		t.Error("expected session invalidated after epoch bump")
	}

	// Sessions map should be empty
	server.mu.Lock()
	count := len(server.sessions)
	server.mu.Unlock()
	if count != 0 {
		t.Errorf("expected empty sessions map after epoch bump, got %d entries", count)
	}
}

func TestInvalidateAllSessions_ClearsAndUpdatesEpoch(t *testing.T) {
	_, base := seedAdminHash(t, "OldPassword123!@#Secure")
	server := newServerWithStore(base)

	// Seed two sessions
	for i := 0; i < 2; i++ {
		tok := generateSessionToken()
		server.mu.Lock()
		server.sessions[tok] = time.Now().Add(sessionTTL)
		server.mu.Unlock()
	}

	server.invalidateAllSessions(5)

	server.mu.Lock()
	count := len(server.sessions)
	server.mu.Unlock()
	if count != 0 {
		t.Errorf("expected 0 sessions after invalidation, got %d", count)
	}
	if got := server.authEpoch.Load(); got != 5 {
		t.Errorf("expected authEpoch=5 after invalidation, got %d", got)
	}
}
