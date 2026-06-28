package ui

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
	aigateway "github.com/jm/security-automation-go/internal/ai/gateway"
	"github.com/jm/security-automation-go/internal/ai/providers"
	aiquota "github.com/jm/security-automation-go/internal/ai/quota"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

type fakeProvider struct {
	name providers.Name
	err  error
}

func (p fakeProvider) Name() providers.Name { return p.name }
func (p fakeProvider) Enabled() bool        { return true }
func (p fakeProvider) Explain(context.Context, ai.ExplainRequest) (ai.ExplainResponse, error) {
	return ai.ExplainResponse{Provider: string(p.name), Model: "fake-model", Explanation: "fake"}, p.err
}
func (p fakeProvider) Quota(context.Context) aiquota.ProviderQuota {
	return aiquota.ProviderQuota{Provider: string(p.name), State: aiquota.Normal}
}

type recordingExplainGateway struct {
	mu     sync.Mutex
	req    ai.ExplainRequest
	called int32
	resp   ai.ExplainResponse
	err    error
}

func (g *recordingExplainGateway) Explain(ctx context.Context, req ai.ExplainRequest) (ai.ExplainResponse, error) {
	_ = ctx
	atomic.AddInt32(&g.called, 1)
	g.mu.Lock()
	g.req = req
	g.mu.Unlock()
	if g.resp.Provider == "" {
		g.resp.Provider = "openai"
	}
	return g.resp, g.err
}

func (g *recordingExplainGateway) Called() int {
	return int(atomic.LoadInt32(&g.called))
}

func (g *recordingExplainGateway) Request() ai.ExplainRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.req
}

func TestProviderManagementReplaceKeyWrites0600AndKeepsDisabled(t *testing.T) {
	srv, db, secretPath := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	legacyFile := filepath.Join(filepath.Dir(secretPath), "openai_api_key")
	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/key", strings.NewReader("confirm_replace=yes&new_api_key=super-secret-token"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
	}
	rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "ai.openai.api_key")
	if err != nil {
		t.Fatalf("load credential: %v", err)
	}
	if !ok || rec.Value != "super-secret-token" {
		t.Fatalf("credential not stored in SQLite: ok=%v value=%q", ok, rec.Value)
	}
	if audit, ok := srv.audit.(*BufferAuditSink); ok {
		if strings.Contains(strings.ToLower(audit.String()), "super-secret-token") {
			t.Fatalf("audit leaked secret: %s", audit.String())
		}
	}
	if _, err := os.Stat(legacyFile); !os.IsNotExist(err) {
		t.Fatalf("legacy secret file should not be written, got err=%v", err)
	}
}

func TestProviderManagementRequiresAuthAndCSRF(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/key", strings.NewReader("confirm_replace=yes&new_api_key=secret"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusFound {
		t.Fatalf("expected auth redirect, got %d", rr.Code)
	}

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req = httptest.NewRequest(http.MethodPost, "/admin/providers/openai/key", strings.NewReader("confirm_replace=yes&new_api_key=secret"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected csrf rejection, got %d", rr.Code)
	}
}

func TestProviderManagementEnableRequiresReadableSecret(t *testing.T) {
	srv, _, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/enable", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected enable refusal, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{"credential not configured in SQLite", "OpenAI"} {
		if !strings.Contains(body, want) {
			t.Fatalf("enable error missing %q: %s", want, body)
		}
	}
}

func TestDashboardConsoleShowsConfiguredButDisabledOpenAI(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "openai-secret", true); err != nil {
		t.Fatalf("seed openai credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/v2/", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	body := rr.Body.String()
	for _, want := range []string{
		"OpenAI",
		"configured",
		"disabled",
	} {
		if !strings.Contains(strings.ToLower(body), strings.ToLower(want)) {
			t.Fatalf("v2 dashboard missing %q: %s", want, body)
		}
	}
	if strings.Contains(strings.ToLower(body), "missing secret") {
		t.Fatalf("v2 dashboard should not show missing secret for configured-but-disabled provider: %s", body)
	}
}

func TestUnifiedProvidersPageShowsAllNineProviders(t *testing.T) {
	srv, _, _ := newTestServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")

	req := httptest.NewRequest(http.MethodGet, "/v2/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		"OpenAI", "Anthropic", "Gemini",
		"AbuseIPDB", "Spamhaus", "VirusTotal",
		"Cloudflare", "CrowdSec", "BetterStack",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("unified providers page missing %q", want)
		}
	}
}

func TestNonAIProviderReplaceKeyWritesToCredentialStore(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/abuseipdb/key", strings.NewReader("confirm_replace=yes&new_api_key=abuse-test-key-xyz"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
	}
	rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), "abuseipdb.api_key")
	if err != nil {
		t.Fatalf("load credential: %v", err)
	}
	if !ok || rec.Value != "abuse-test-key-xyz" {
		t.Fatalf("credential not stored: ok=%v value=%q", ok, rec.Value)
	}
}

func TestNonAIProviderReplaceKeyAutoTestsAndMarksHealthy(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, nil)
	if err := saveProviderRuntimeSnapshot(context.Background(), sqlite.NewSetupStore(db), "abuseipdb", providerRuntimeSnapshot{Enabled: true}); err != nil {
		t.Fatalf("seed runtime snapshot: %v", err)
	}
	called := make(chan struct{}, 1)
	srv.validateAbuseIPDB = func(context.Context, string) error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/abuseipdb/key", strings.NewReader("confirm_replace=yes&new_api_key=abuse-live-key"))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
	}

	select {
	case <-called:
	case <-time.After(5 * time.Second):
		t.Fatal("expected AbuseIPDB auto-test to run after key replace")
	}

	var state providerRuntimeSnapshot
	var ok bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, ok, _ = loadProviderRuntimeSnapshot(context.Background(), sqlite.NewSetupStore(db), "abuseipdb")
		if ok && state.Healthy && state.LastTestStatus == providerTestReady {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		t.Fatal("expected persisted runtime state")
	}
	if !state.Healthy {
		t.Fatalf("expected abuseipdb to become healthy after auto-test, got %#v", state)
	}
	if state.LastLatencyMS < 1 {
		t.Fatalf("expected positive latency after auto-test, got %d", state.LastLatencyMS)
	}
	if state.LastTestStatus != providerTestReady {
		t.Fatalf("expected ready test status, got %q", state.LastTestStatus)
	}
}

func TestProvidersTestAllSchedulesAIAndNonAIRefreshes(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	store := sqlite.NewSetupStore(db)
	if err := saveProviderRuntimeSnapshot(context.Background(), store, "abuseipdb", providerRuntimeSnapshot{Enabled: true}); err != nil {
		t.Fatalf("seed abuse runtime snapshot: %v", err)
	}
	if err := saveAIProviderStateToStore(context.Background(), store, AIProviderState{
		OpenAI: AIProviderRecord{Enabled: true, Model: "gpt-4.1-mini"},
	}); err != nil {
		t.Fatalf("seed ai runtime state: %v", err)
	}
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "abuseipdb.api_key", "abuse-live-key", true); err != nil {
		t.Fatalf("seed abuse credential: %v", err)
	}
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "openai-live-key", true); err != nil {
		t.Fatalf("seed openai credential: %v", err)
	}

	abuseCalled := make(chan struct{}, 1)
	srv.validateAbuseIPDB = func(context.Context, string) error {
		select {
		case abuseCalled <- struct{}{}:
		default:
		}
		return nil
	}
	gateway := &recordingExplainGateway{}
	srv.aiExplain = gateway

	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)
	req := httptest.NewRequest(http.MethodPost, "/admin/providers/test-all", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
	}
	select {
	case <-abuseCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("expected AbuseIPDB refresh to run")
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) && gateway.Called() == 0 {
		time.Sleep(50 * time.Millisecond)
	}
	if gateway.Called() == 0 {
		t.Fatal("expected AI refresh to run")
	}
}

func TestProviderHealthRefresherRefreshesEnabledProviders(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, nil)
	store := sqlite.NewSetupStore(db)
	if err := saveProviderRuntimeSnapshot(context.Background(), store, "abuseipdb", providerRuntimeSnapshot{Enabled: true}); err != nil {
		t.Fatalf("seed runtime snapshot: %v", err)
	}
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "abuseipdb.api_key", "abuse-live-key", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	called := make(chan struct{}, 1)
	srv.validateAbuseIPDB = func(context.Context, string) error {
		select {
		case called <- struct{}{}:
		default:
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv.StartProviderHealthRefreshers(ctx, 10*time.Millisecond)

	select {
	case <-called:
	case <-time.After(2 * time.Second):
		t.Fatal("expected AbuseIPDB refresher to run")
	}

	var state providerRuntimeSnapshot
	var ok bool
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, ok, _ = loadProviderRuntimeSnapshot(context.Background(), store, "abuseipdb")
		if ok && state.Healthy && state.LastTestStatus == providerTestReady {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !ok {
		t.Fatal("expected persisted runtime state")
	}
	if !state.Healthy {
		t.Fatalf("expected abuseipdb to become healthy after refresher, got %#v", state)
	}
	if state.LastLatencyMS < 1 {
		t.Fatalf("expected positive latency after refresher, got %d", state.LastLatencyMS)
	}
	if state.LastTestStatus != providerTestReady {
		t.Fatalf("expected ready test status, got %q", state.LastTestStatus)
	}
}

func TestAIProviderStatePersistsToSQLiteAndSurvivesReload(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "test-key", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/enable", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after enable, got %d: %s", rr.Code, rr.Body.String())
	}

	// Verify persisted to SQLite
	store := sqlite.NewSetupStore(db)
	v, ok, err := store.GetSetting(context.Background(), "ai.openai.enabled")
	if err != nil {
		t.Fatalf("read sqlite: %v", err)
	}
	if !ok || v != "true" {
		t.Fatalf("expected ai.openai.enabled=true in sqlite, got ok=%v v=%q", ok, v)
	}

	// Verify the view reflects the persisted state
	req2 := httptest.NewRequest(http.MethodGet, "/v2/providers", nil)
	req2.AddCookie(cookie)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("providers page %d: %s", rr2.Code, rr2.Body.String())
	}
	// V2 providers page renders the enabled state as lowercase "enabled".
	if !strings.Contains(rr2.Body.String(), "enabled") {
		t.Fatalf("providers page does not show enabled state after sqlite-persisted enable: %s", rr2.Body.String())
	}
}

func TestProviderManagementEnableClearsStaleDiagnostics(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "test-key", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	now := time.Date(2026, 6, 14, 10, 0, 0, 0, time.UTC)
	if err := saveAIProviderStateToStore(context.Background(), sqlite.NewSetupStore(db), AIProviderState{
		OpenAI: AIProviderRecord{
			Enabled:           false,
			Model:             "gpt-4.1-mini",
			Healthy:           false,
			LastTestAt:        now,
			LastFailureAt:     now,
			LastTestStatus:    providerTestDisabledByOperator,
			LastTestLatencyMS: 99,
			LastErrorCode:     providerTestDisabledByOperator,
		},
	}); err != nil {
		t.Fatalf("seed ai state: %v", err)
	}
	srv.aiExplain = nil
	srv.aiExplainBuilder = nil

	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)
	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/enable", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after enable, got %d: %s", rr.Code, rr.Body.String())
	}

	state, _, err := loadAIProviderStateFromStore(context.Background(), sqlite.NewSetupStore(db))
	if err != nil {
		t.Fatalf("load state from sqlite: %v", err)
	}
	if !state.OpenAI.Enabled {
		t.Fatalf("expected provider enabled, got %#v", state.OpenAI)
	}
	if state.OpenAI.Healthy {
		t.Fatalf("enable should not preserve stale healthy state: %#v", state.OpenAI)
	}
	if state.OpenAI.LastTestStatus != "" || state.OpenAI.LastErrorCode != "" {
		t.Fatalf("enable should clear stale diagnostics, got %#v", state.OpenAI)
	}
	if !state.OpenAI.LastTestAt.IsZero() || !state.OpenAI.LastSuccessAt.IsZero() || !state.OpenAI.LastFailureAt.IsZero() {
		t.Fatalf("enable should clear stale timestamps, got %#v", state.OpenAI)
	}
	if state.OpenAI.LastTestLatencyMS != 0 {
		t.Fatalf("enable should clear stale latency, got %#v", state.OpenAI)
	}
}

func TestProviderManagementTestProviderUsesStubAndRedacts(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "test-secret", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	store := sqlite.NewSetupStore(db)
	if err := saveAIProviderStateToStore(context.Background(), store, AIProviderState{
		OpenAI: AIProviderRecord{Enabled: true, Model: "gpt-4.1-mini"},
	}); err != nil {
		t.Fatalf("seed state: %v", err)
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	gateway := &recordingExplainGateway{err: &providers.Error{Provider: providers.OpenAI, StatusCode: http.StatusTooManyRequests, Reason: "rate limited"}}
	srv.aiExplain = gateway
	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/test", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after test, got %d", rr.Code)
	}
	if gateway.Called() < 1 {
		t.Fatalf("expected AI explain gateway to be used, got %d", gateway.Called())
	}
	if req := gateway.Request(); req.ProviderPreference != "openai" || req.SubjectType != ai.SubjectProvider {
		t.Fatalf("unexpected gateway request: %+v", req)
	}
	state, _, err := loadAIProviderStateFromStore(context.Background(), sqlite.NewSetupStore(db))
	if err != nil {
		t.Fatalf("load state from sqlite: %v", err)
	}
	if state.OpenAI.LastTestStatus != providerTestRateLimited {
		t.Fatalf("expected rate limited test status, got %#v", state.OpenAI)
	}
	if state.OpenAI.LastTestLatencyMS < 0 {
		t.Fatalf("invalid latency stored: %#v", state.OpenAI)
	}
	if audit, ok := srv.audit.(*BufferAuditSink); ok {
		for _, forbidden := range []string{"test-secret", "rate limited"} {
			if strings.Contains(strings.ToLower(audit.String()), strings.ToLower(forbidden)) {
				t.Fatalf("audit leaked %q: %s", forbidden, audit.String())
			}
		}
	}

	req2 := httptest.NewRequest(http.MethodGet, "/v2/providers", nil)
	req2.AddCookie(cookie)
	rr2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("expected providers page after test, got %d", rr2.Code)
	}
	body := strings.ToLower(rr2.Body.String())
	if !strings.Contains(body, "rate limited") {
		t.Fatalf("providers page should show short rate-limit diagnostic: %s", rr2.Body.String())
	}
}

func TestProviderManagementTestProviderSkipsNetworkWhenDisabled(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"AI_PROVIDER_OPENAI_ENABLED": "false",
		"AI_PROVIDER_OPENAI_MODEL":   "gpt-4.1-mini",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "test-secret", true); err != nil {
		t.Fatalf("seed credential: %v", err)
	}
	gateway := &recordingExplainGateway{}
	srv.aiExplain = gateway
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/test", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect after disabled test, got %d", rr.Code)
	}
	if gateway.Called() != 0 {
		t.Fatalf("disabled provider must not invoke gateway path, got %d calls", gateway.Called())
	}
	state, _, err := loadAIProviderStateFromStore(context.Background(), sqlite.NewSetupStore(db))
	if err != nil {
		t.Fatalf("load state from sqlite: %v", err)
	}
	if state.OpenAI.LastTestStatus != providerTestDisabledByOperator {
		t.Fatalf("expected disabled-by-operator test status, got %#v", state.OpenAI)
	}
}

func TestAIProviderManualAndAutomaticRefreshShareValidationPath(t *testing.T) {
	t.Run("manual test", func(t *testing.T) {
		srv, db, _ := newCredentialStoreServer(t, map[string]string{
			"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
		})
		if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "test-key", true); err != nil {
			t.Fatalf("seed credential: %v", err)
		}
		if err := saveAIProviderStateToStore(context.Background(), sqlite.NewSetupStore(db), AIProviderState{
			OpenAI: AIProviderRecord{Enabled: true, Model: "gpt-4.1-mini"},
		}); err != nil {
			t.Fatalf("seed state: %v", err)
		}
		gateway := &recordingExplainGateway{err: errors.New("opaque failure")}
		srv.aiExplain = gateway

		cookie := loginCookie(t, srv, "test-password-123!@#")
		req := httptest.NewRequest(http.MethodPost, "/admin/providers/openai/test", strings.NewReader(""))
		req.AddCookie(cookie)
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
		rr := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusSeeOther {
			t.Fatalf("expected redirect after test, got %d: %s", rr.Code, rr.Body.String())
		}

		state, _, err := loadAIProviderStateFromStore(context.Background(), sqlite.NewSetupStore(db))
		if err != nil {
			t.Fatalf("load state: %v", err)
		}
		if state.OpenAI.LastTestStatus != providerTestUnknownError || state.OpenAI.LastErrorCode != providerTestUnknownError {
			t.Fatalf("manual test should classify opaque failures through shared path, got %#v", state.OpenAI)
		}
	})

	t.Run("automatic refresh", func(t *testing.T) {
		srv, db, _ := newCredentialStoreServer(t, map[string]string{
			"AI_PROVIDER_OPENAI_MODEL": "gpt-4.1-mini",
		})
		if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "test-key", true); err != nil {
			t.Fatalf("seed credential: %v", err)
		}
		if err := saveAIProviderStateToStore(context.Background(), sqlite.NewSetupStore(db), AIProviderState{
			OpenAI: AIProviderRecord{Enabled: true, Model: "gpt-4.1-mini"},
		}); err != nil {
			t.Fatalf("seed state: %v", err)
		}
		gateway := &recordingExplainGateway{err: errors.New("opaque failure")}
		srv.aiExplain = gateway

		srv.refreshAIProviderHealth(context.Background(), AIProviderOpenAI)

		state, _, err := loadAIProviderStateFromStore(context.Background(), sqlite.NewSetupStore(db))
		if err != nil {
			t.Fatalf("load state: %v", err)
		}
		if state.OpenAI.LastTestStatus != providerTestUnknownError || state.OpenAI.LastErrorCode != providerTestUnknownError {
			t.Fatalf("automatic refresh should classify opaque failures through shared path, got %#v", state.OpenAI)
		}
	})
}

func TestNonAIProviderTogglePersistsRuntimeState(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, nil)
	cookie := loginCookie(t, srv, "test-password-123!@#")
	csrf := srv.csrfTokenFor(cookie.Value)

	req := httptest.NewRequest(http.MethodPost, "/admin/providers/abuseipdb/disable", strings.NewReader(""))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-CSRF-Token", csrf)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
	}
	snapshot, ok, err := loadProviderRuntimeSnapshot(context.Background(), sqlite.NewSetupStore(db), "abuseipdb")
	if err != nil {
		t.Fatalf("load runtime snapshot: %v", err)
	}
	if !ok {
		t.Fatal("expected runtime snapshot to be present after toggle")
	}
	if snapshot.Enabled {
		t.Fatalf("expected abuseipdb disabled snapshot, got %#v", snapshot)
	}
}

func TestNormalizeAIConfigRestoresDefaultModels(t *testing.T) {
	cfg := ai.Config{
		OpenAI:    ai.ProviderConfig{Enabled: true, Model: ""},
		Anthropic: ai.ProviderConfig{Enabled: true, Model: ""},
		Gemini:    ai.ProviderConfig{Enabled: true, Model: ""},
	}
	got := normalizeAIConfig(cfg)
	if got.OpenAI.Model != ai.DefaultOpenAIModel {
		t.Errorf("openai: want %q, got %q", ai.DefaultOpenAIModel, got.OpenAI.Model)
	}
	if got.Anthropic.Model != ai.DefaultAnthropicModel {
		t.Errorf("anthropic: want %q, got %q", ai.DefaultAnthropicModel, got.Anthropic.Model)
	}
	if got.Gemini.Model != ai.DefaultGeminiModel {
		t.Errorf("gemini: want %q, got %q", ai.DefaultGeminiModel, got.Gemini.Model)
	}

	// Disabled providers must not get a model injected.
	cfgDisabled := ai.Config{
		OpenAI:    ai.ProviderConfig{Enabled: false, Model: ""},
		Anthropic: ai.ProviderConfig{Enabled: false, Model: ""},
		Gemini:    ai.ProviderConfig{Enabled: false, Model: ""},
	}
	gotDisabled := normalizeAIConfig(cfgDisabled)
	if gotDisabled.OpenAI.Model != "" || gotDisabled.Anthropic.Model != "" || gotDisabled.Gemini.Model != "" {
		t.Errorf("disabled providers must not get default models injected: %+v", gotDisabled)
	}

	// Explicitly-set models must not be overwritten.
	cfgWithModel := ai.Config{
		OpenAI:    ai.ProviderConfig{Enabled: true, Model: "gpt-3.5-turbo"},
		Anthropic: ai.ProviderConfig{Enabled: true, Model: "claude-2"},
		Gemini:    ai.ProviderConfig{Enabled: true, Model: "gemini-pro"},
	}
	gotWithModel := normalizeAIConfig(cfgWithModel)
	if gotWithModel.OpenAI.Model != "gpt-3.5-turbo" {
		t.Errorf("openai: explicit model should not be overwritten, got %q", gotWithModel.OpenAI.Model)
	}
}

func TestNormalizeAIConfigEnablesExplainWhenConfiguredProviderExists(t *testing.T) {
	cfg := ai.Config{
		Enabled: false,
		OpenAI: ai.ProviderConfig{
			Enabled: true,
			Model:   "",
			APIKey:  "openai-secret",
		},
	}
	got := normalizeAIConfig(cfg)
	if !got.Enabled {
		t.Fatalf("expected AI explain to auto-enable when a configured provider exists: %+v", got)
	}
	if got.OpenAI.Model != ai.DefaultOpenAIModel {
		t.Fatalf("expected default OpenAI model to be restored, got %q", got.OpenAI.Model)
	}
}

func TestAIExplainBecomesActiveAfterCredentialRotation(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, map[string]string{
		"UI_SECRET":                     "ui-secret-value",
		"AI_PROVIDER_OPENAI_ENABLED":    "true",
		"AI_PROVIDER_OPENAI_MODEL":      "gpt-4.1-mini",
		"AI_PROVIDER_ANTHROPIC_ENABLED": "false",
		"AI_PROVIDER_GEMINI_ENABLED":    "false",
	})
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "ai.openai.api_key", "openai-secret", true); err != nil {
		t.Fatalf("seed openai credential: %v", err)
	}
	auditSink, ok := srv.audit.(*BufferAuditSink)
	if !ok {
		t.Fatalf("expected buffer audit sink, got %T", srv.audit)
	}
	srv.aiExplainBuilder = func(cfg ai.Config) aigateway.Gateway {
		provs := make([]providers.Provider, 0, 1)
		if cfg.OpenAI.Enabled && strings.TrimSpace(cfg.OpenAI.APIKey) != "" {
			provs = append(provs, fakeProvider{name: providers.OpenAI})
		}
		return aigateway.NewService(cfg, provs, nil, auditSink)
	}
	if err := srv.rebuildAIExplainFromState(); err != nil {
		t.Fatalf("rebuild AI explain: %v", err)
	}
	if srv.aiExplain == nil {
		t.Fatal("expected AI explain gateway to be active after credential rotation")
	}
	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodPost, "/ui/ai/explain", strings.NewReader(`{"subject_type":"provider","subject_id":"openai","provider_preference":"auto"}`))
	req.AddCookie(cookie)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", srv.csrfTokenFor(cookie.Value))
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("expected AI explain to work after credential rotation, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(rr.Body.String(), `"provider":"openai"`) {
		t.Fatalf("expected AI explain response to use configured provider, got: %s", rr.Body.String())
	}
}

// TestNonAIProviderReplaceKeyUpdatesDisplay verifies that after a Replace Key POST,
// the /providers page immediately shows "CONFIGURED" for the provider without restart.
func TestNonAIProviderReplaceKeyUpdatesDisplay(t *testing.T) {
	for _, tc := range []struct {
		slug    string
		credKey string
	}{
		{"spamhaus", "spamhaus.api_key"},
		{"virustotal", "virustotal.api_key"},
		{"abuseipdb", "abuseipdb.api_key"},
	} {
		t.Run(tc.slug, func(t *testing.T) {
			srv, db, _ := newCredentialStoreServer(t, nil)
			cookie := loginCookie(t, srv, "test-password-123!@#")
			csrf := srv.csrfTokenFor(cookie.Value)

			// POST Replace Key
			body := "confirm_replace=yes&new_api_key=placeholder-" + tc.slug
			req := httptest.NewRequest(http.MethodPost, "/admin/providers/"+tc.slug+"/key", strings.NewReader(body))
			req.AddCookie(cookie)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-CSRF-Token", csrf)
			rr := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr, req)
			if rr.Code != http.StatusSeeOther {
				t.Fatalf("expected redirect, got %d: %s", rr.Code, rr.Body.String())
			}

			// Verify written under the dotted key name
			rec, ok, err := sqlite.NewCredentialStore(db).Get(context.Background(), tc.credKey)
			if err != nil {
				t.Fatalf("load credential: %v", err)
			}
			if !ok || rec.Value != "placeholder-"+tc.slug {
				t.Fatalf("credential not stored under %q: ok=%v value=%q", tc.credKey, ok, rec.Value)
			}

			// Verify GET /providers now shows CONFIGURED for this provider
			req2 := httptest.NewRequest(http.MethodGet, "/v2/providers", nil)
			req2.AddCookie(cookie)
			rr2 := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rr2, req2)
			if rr2.Code != http.StatusOK {
				t.Fatalf("GET /providers: %d", rr2.Code)
			}
			html := rr2.Body.String()
			if !strings.Contains(strings.ToUpper(html), "CONFIGURED") {
				t.Errorf("%s: /providers page must show CONFIGURED after Replace Key", tc.slug)
			}
			if strings.Contains(html, "placeholder-"+tc.slug) {
				t.Errorf("%s: raw key must never appear in /providers HTML", tc.slug)
			}
		})
	}
}

// TestNonAIProviderKeyNeverLeaksInHTML verifies that the raw key value is never rendered,
// only a masked representation.
func TestNonAIProviderKeyNeverLeaksInHTML(t *testing.T) {
	srv, db, _ := newCredentialStoreServer(t, nil)
	// Seed a key directly into the credential store
	const syntheticKey = "placeholder-spamhaus-value"
	if err := sqlite.NewCredentialStore(db).Set(context.Background(), "spamhaus.api_key", syntheticKey, true); err != nil {
		t.Fatalf("seed: %v", err)
	}

	cookie := loginCookie(t, srv, "test-password-123!@#")
	req := httptest.NewRequest(http.MethodGet, "/v2/providers", nil)
	req.AddCookie(cookie)
	rr := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rr, req)

	html := rr.Body.String()
	if strings.Contains(html, syntheticKey) {
		t.Error("raw Spamhaus API key must never appear in /providers HTML")
	}
	if !strings.Contains(strings.ToUpper(html), "CONFIGURED") {
		t.Error("/providers page must show CONFIGURED for Spamhaus after key is seeded")
	}
}
