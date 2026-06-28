package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

const uiSessionCookieName = "ui_session"

func TestUIFreshInstallWizardAndConservativeRestart(t *testing.T) {
	stateDir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.UI.Enabled = true
	cfg.UI.Addr = "127.0.0.1:" + freePort(t)
	cfg.StateDir = stateDir
	cfg.FinalizePaths()
	cfg.UI.ProviderStateFile = filepath.Join(stateDir, "runtime", "ai-providers.env")

	cancel, done := startUIMode(t, cfg)

	step1Body := getBody(t, "http://"+cfg.UI.Addr+"/setup/step/1")
	if !strings.Contains(step1Body, "Create administrator password") {
		t.Fatalf("setup wizard not reachable on fresh install: %s", step1Body)
	}

	assertFileMode(t, filepath.Join(stateDir, "secret.key"), 0o600)
	assertFileExists(t, filepath.Join(stateDir, "runtime.db"))

	const testAdminPass = "Password123!@#Admin"
	minimalWizardComplete(t, cfg, stateDir, testAdminPass)

	// Re-authenticate and smoke the main operator pages on the live fresh-install instance.
	client := &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	session := loginAndGetSessionCookie(t, client, "http://"+cfg.UI.Addr, testAdminPass)
	dashboardBody := getBodyWithCookie(t, client, "http://"+cfg.UI.Addr+"/v2/", session)
	if !strings.Contains(dashboardBody, "v2-sidebar") {
		t.Fatalf("dashboard should render the v2 shell: %s", dashboardBody)
	}
	healthBody := getBodyWithCookie(t, client, "http://"+cfg.UI.Addr+"/v2/health", session)
	if strings.Contains(healthBody, "state.db") {
		t.Fatalf("health center must not mention state.db: %s", healthBody)
	}

	db, err := sqlite.New(stateDir)
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	defer db.Close()
	setupStore := sqlite.NewSetupStore(db)
	if ok, err := setupStore.IsComplete(context.Background()); err != nil || !ok {
		t.Fatalf("expected setup_complete=true after minimal wizard, ok=%v err=%v", ok, err)
	}
	if v, ok, err := setupStore.GetSetting(context.Background(), "mutations_enabled"); err != nil {
		t.Fatalf("load mutations_enabled: %v", err)
	} else if ok && v == "true" {
		t.Fatalf("expected production mutations to stay disabled on minimal wizard")
	}

	secretKeyBefore := readFileBytes(t, filepath.Join(stateDir, "secret.key"))

	cancel()
	waitForUIExit(t, done)

	// Conservative restart on the same state directory must preserve DB and master key.
	cfg.UI.Addr = "127.0.0.1:" + freePort(t)
	cancel2, done2 := startUIMode(t, cfg)
	defer func() {
		cancel2()
		waitForUIExit(t, done2)
	}()

	secretKeyAfter := readFileBytes(t, filepath.Join(stateDir, "secret.key"))
	if string(secretKeyBefore) != string(secretKeyAfter) {
		t.Fatal("secret.key changed across conservative restart")
	}

	client = &http.Client{
		Timeout: 20 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get("http://" + cfg.UI.Addr + "/")
	if err != nil {
		t.Fatalf("dashboard request after restart: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		t.Fatalf("expected redirect after conservative restart, got %d", resp.StatusCode)
	}
	if loc := resp.Header.Get("Location"); !strings.Contains(loc, "/login") {
		t.Fatalf("expected login redirect after setup_complete=true, got %q", loc)
	}
}

func TestConfigAllowsFreshInstallWithoutCloudflareBootstrapSecrets(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "")
	t.Setenv("CF_ZONE_ID", "")
	t.Setenv("UI_ENABLED", "1")
	t.Setenv("STATE_DIR", t.TempDir())
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("expected fresh-install config to load: %v", err)
	}
	if cfg.Cloudflare.APIToken != "" || cfg.Cloudflare.ZoneID != "" {
		t.Fatalf("expected cloudflare bootstrap secrets to remain empty, got %+v", cfg.Cloudflare)
	}
}

func startUIMode(t *testing.T, cfg *config.Config) (context.CancelFunc, chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	go func() {
		done <- runUI(ctx, logger, cfg)
	}()
	waitForHTTPReady(t, "http://"+cfg.UI.Addr+"/setup/step/1", done)
	return cancel, done
}

func waitForHTTPReady(t *testing.T, url string, done <-chan error) {
	t.Helper()
	client := &http.Client{Timeout: 500 * time.Millisecond}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case err := <-done:
			t.Fatalf("ui exited before becoming ready: %v", err)
		default:
		}
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("ui did not become ready at %s", url)
}

func waitForUIExit(t *testing.T, done <-chan error) {
	t.Helper()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ui exited with error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for ui shutdown")
	}
}

func getBody(t *testing.T, url string) string {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

func minimalWizardComplete(t *testing.T, cfg *config.Config, stateDir, password string) {
	t.Helper()
	client := &http.Client{
		// Step 1 performs a bcrypt hash; under full-suite load this can exceed a few seconds.
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Create admin password
	resp, err := client.PostForm("http://"+cfg.UI.Addr+"/setup/step/1", url.Values{
		"new_password":     {password},
		"confirm_password": {password},
	})
	if err != nil {
		t.Fatalf("POST step 1: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected redirect from step 1, got %d: %s", resp.StatusCode, string(body))
	}
	session := ""
	for _, c := range resp.Cookies() {
		if c.Name == uiSessionCookieName {
			session = c.Value
			break
		}
	}
	if session == "" {
		t.Fatal("missing session cookie after step 1")
	}

	csrf := getCSRF(t, client, "http://"+cfg.UI.Addr+"/setup/step/2", session)
	csrf = postAndGetNextCSRF(t, client, "http://"+cfg.UI.Addr, "/setup/step/2", url.Values{
		"csrf_token": {csrf},
		"skip":       {"1"},
	}, session)
	csrf = postAndGetNextCSRF(t, client, "http://"+cfg.UI.Addr, "/setup/step/3", url.Values{
		"csrf_token": {csrf},
		"skip":       {"1"},
	}, session)
	csrf = postAndGetNextCSRF(t, client, "http://"+cfg.UI.Addr, "/setup/step/4", url.Values{
		"csrf_token": {csrf},
		"skip":       {"1"},
	}, session)
	csrf = postAndGetNextCSRF(t, client, "http://"+cfg.UI.Addr, "/setup/step/5", url.Values{
		"csrf_token": {csrf},
		"skip":       {"1"},
	}, session)
	csrf = postAndGetNextCSRF(t, client, "http://"+cfg.UI.Addr, "/setup/step/6", url.Values{
		"csrf_token": {csrf},
		"skip":       {"1"},
	}, session)
	postAndCheckLocation(t, client, "http://"+cfg.UI.Addr, "/setup/step/7", url.Values{
		"csrf_token": {csrf},
		"skip":       {"1"},
	}, session)
	// Step 8: Runtime summary — no form, just verify content and navigate forward.
	step8 := getBodyWithCookie(t, client, "http://"+cfg.UI.Addr+"/setup/step/8", session)
	if !strings.Contains(step8, "Runtime summary") && !strings.Contains(step8, "Detected Environment") {
		t.Fatalf("expected runtime summary after minimal wizard, got: %s", step8)
	}
	csrf = getCSRF(t, client, "http://"+cfg.UI.Addr+"/setup/step/9", session)
	postNoRedirect(t, client, "http://"+cfg.UI.Addr, "/setup/step/9", url.Values{
		"csrf_token": {csrf},
	}, session)

	db, err := sqlite.New(stateDir)
	if err != nil {
		t.Fatalf("reopen sqlite after wizard: %v", err)
	}
	defer db.Close()
	setupStore := sqlite.NewSetupStore(db)
	if ok, err := setupStore.IsComplete(context.Background()); err != nil || !ok {
		t.Fatalf("expected setup_complete=true after minimal wizard, ok=%v err=%v", ok, err)
	}
}

func loginAndGetSessionCookie(t *testing.T, client *http.Client, baseURL, password string) string {
	t.Helper()
	resp, err := client.PostForm(baseURL+"/login", url.Values{"password": {password}})
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		if c.Name == uiSessionCookieName {
			return c.Value
		}
	}
	t.Fatalf("login did not return a session cookie")
	return ""
}

func postAndGetNextCSRF(t *testing.T, client *http.Client, baseURL, path string, form url.Values, session string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", uiSessionCookieName+"="+session)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected redirect from %s, got %d: %s", path, resp.StatusCode, string(body))
	}
	next := resp.Header.Get("Location")
	if next == "" {
		t.Fatalf("missing redirect location after POST %s", path)
	}
	return getCSRF(t, client, baseURL+next, session)
}

func postAndCheckLocation(t *testing.T, client *http.Client, baseURL, path string, form url.Values, session string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", uiSessionCookieName+"="+session)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected redirect from %s, got %d: %s", path, resp.StatusCode, string(body))
	}
	next := resp.Header.Get("Location")
	if next == "" {
		t.Fatalf("missing redirect location after POST %s", path)
	}
	return next
}

func postNoRedirect(t *testing.T, client *http.Client, baseURL, path string, form url.Values, session string) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, baseURL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", uiSessionCookieName+"="+session)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound && resp.StatusCode != http.StatusSeeOther {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected redirect from %s, got %d: %s", path, resp.StatusCode, string(body))
	}
}

func getCSRF(t *testing.T, client *http.Client, url string, session string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	req.Header.Set("Cookie", uiSessionCookieName+"="+session)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", url, err)
	}
	csrf := extractCSRFToken(string(body))
	if csrf == "" {
		t.Fatalf("missing csrf token on %s", url)
	}
	return csrf
}

func getBodyWithCookie(t *testing.T, client *http.Client, url string, session string) string {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	req.Header.Set("Cookie", uiSessionCookieName+"="+session)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body %s: %v", url, err)
	}
	return string(body)
}

func extractCSRFToken(body string) string {
	re := regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)
	m := re.FindStringSubmatch(body)
	if len(m) != 2 {
		return ""
	}
	return m[1]
}

func freePort(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen on ephemeral port: %v", err)
	}
	defer ln.Close()
	return fmt.Sprintf("%d", ln.Addr().(*net.TCPAddr).Port)
}

func assertFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected file %s to exist: %v", path, err)
	}
}

func assertFileMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("expected %s mode %04o, got %04o", path, want, got)
	}
}

func readFileBytes(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return data
}
