package ui_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/ui"
)

// fakeSetupStore implements ui.SetupStorer for tests.
type fakeSetupStore struct {
	step     int
	complete bool
	settings map[string]string
}

func (f *fakeSetupStore) GetCurrentStep(_ context.Context) (int, error) { return f.step, nil }
func (f *fakeSetupStore) SetCurrentStep(_ context.Context, s int) error  { f.step = s; return nil }
func (f *fakeSetupStore) IsComplete(_ context.Context) (bool, error)     { return f.complete, nil }
func (f *fakeSetupStore) MarkComplete(_ context.Context) error           { f.complete = true; return nil }
func (f *fakeSetupStore) GetSetting(_ context.Context, k string) (string, bool, error) {
	v, ok := f.settings[k]
	return v, ok, nil
}
func (f *fakeSetupStore) SetSetting(_ context.Context, k, v string) error {
	if f.settings == nil {
		f.settings = map[string]string{}
	}
	f.settings[k] = v
	return nil
}

func newTestServerWithSetup(t *testing.T, store ui.SetupStorer) *ui.Server {
	t.Helper()
	dataDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.UI.Enabled = true
	cfg.UI.Addr = "127.0.0.1:0"
	cfg.UI.AdminPasswordFile = dataDir + "/admin_password"
	cfg.UI.InitialPasswordFile = dataDir + "/initial-admin-password"
	cfg.UI.SecretFile = dataDir + "/secret"
	cfg.UI.ProviderStateFile = dataDir + "/ai-providers.env"
	cfg.StateDir = dataDir
	srv, err := ui.NewServer(cfg, ui.Options{
		SetupStore: store,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	return srv
}

func TestSetupGuard_IncompleteRedirectsToSetup(t *testing.T) {
	store := &fakeSetupStore{step: 1, complete: false}
	srv := newTestServerWithSetup(t, store)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("want 302, got %d", w.Code)
	}
	loc := w.Header().Get("Location")
	if !strings.HasPrefix(loc, "/setup") {
		t.Errorf("want redirect to /setup/*, got %q", loc)
	}
}

func TestSetupGuard_CompleteAllowsDashboard(t *testing.T) {
	store := &fakeSetupStore{step: 9, complete: true}
	srv := newTestServerWithSetup(t, store)

	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Login page should be reachable when setup is complete without redirect to /setup
	if w.Code == http.StatusFound && strings.HasPrefix(w.Header().Get("Location"), "/setup") {
		t.Error("complete setup should not redirect to /setup")
	}
}

func TestSetupGuard_SetupRoutesAlwaysAccessible(t *testing.T) {
	store := &fakeSetupStore{step: 1, complete: false}
	srv := newTestServerWithSetup(t, store)

	req := httptest.NewRequest("GET", "/setup/step/1", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	// Must NOT redirect back to /setup (infinite loop)
	if w.Code == http.StatusFound && strings.HasPrefix(w.Header().Get("Location"), "/setup") {
		t.Error("setup route must not redirect to another setup route")
	}
}

func TestSetupGuard_NilStoreAllsThrough(t *testing.T) {
	// When SetupStore is nil (legacy installs), guard must be a no-op.
	srv := newTestServerWithSetup(t, nil)

	req := httptest.NewRequest("GET", "/login", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code == http.StatusFound && strings.HasPrefix(w.Header().Get("Location"), "/setup") {
		t.Error("nil SetupStore must not redirect to setup")
	}
}
