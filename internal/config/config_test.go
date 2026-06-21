package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestConfig_Load_Default(t *testing.T) {
	// Set required env vars
	os.Setenv("CF_API_TOKEN", "test-token")
	os.Setenv("CF_ZONE_ID", "test-zone")
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("failed to load default config: %v", err)
	}

	if cfg.Version != SchemaVersion {
		t.Errorf("expected version %s, got %s", SchemaVersion, cfg.Version)
	}
	if cfg.Global.AppEnv != "production" {
		t.Errorf("expected default env production, got %s", cfg.Global.AppEnv)
	}
	if cfg.Runtime.Profile != RuntimeProfileSingleNode {
		t.Errorf("expected default runtime profile %s, got %s", RuntimeProfileSingleNode, cfg.Runtime.Profile)
	}
}

func TestConfig_Load_YAML(t *testing.T) {
	os.Setenv("CF_API_TOKEN", "env-token")
	defer os.Unsetenv("CF_API_TOKEN")

	content := `
version: v1
global:
  app_env: development
cloudflare:
  api_token: yaml-token
  zone_id: yaml-zone
interval: 30s
runtime:
  profile: strict-ha
abuseipdb:
  reporting_enabled: true
`
	tmpfile, _ := os.CreateTemp("", "config*.yaml")
	defer os.Remove(tmpfile.Name())
	tmpfile.Write([]byte(content))
	tmpfile.Close()

	// 1. YAML should override defaults
	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to load YAML config: %v", err)
	}

	if cfg.Global.AppEnv != "development" {
		t.Errorf("expected env development from YAML, got %s", cfg.Global.AppEnv)
	}

	// 2. Env should override YAML
	if cfg.Cloudflare.APIToken != "env-token" {
		t.Errorf("expected api_token from env to override YAML, got %s", cfg.Cloudflare.APIToken)
	}

	if cfg.Interval != 30*time.Second {
		t.Errorf("expected interval 30s from YAML, got %s", cfg.Interval)
	}
	if cfg.Runtime.Profile != RuntimeProfileStrictHA {
		t.Errorf("expected runtime profile strict-ha from YAML, got %s", cfg.Runtime.Profile)
	}
	if cfg.AbuseIPDB.ReportingEnabled == nil || !*cfg.AbuseIPDB.ReportingEnabled {
		t.Fatalf("expected abuseipdb.reporting_enabled=true from YAML, got %v", cfg.AbuseIPDB.ReportingEnabled)
	}
}

func TestConfig_HTTPErrorIntel_DefaultsSurviveOmittedYAML(t *testing.T) {
	os.Setenv("CF_API_TOKEN", "env-token")
	os.Setenv("CF_ZONE_ID", "test-zone")
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")

	// A YAML file that says nothing about http_error_intel must not disable
	// nginxerrors ingestion for existing deployments — Load overlays YAML
	// onto DefaultConfig(), so the section's defaults (Enabled=true,
	// EnforceMode=false) must survive untouched.
	content := `
version: v1
global:
  app_env: development
`
	tmpfile, _ := os.CreateTemp("", "config*.yaml")
	defer os.Remove(tmpfile.Name())
	tmpfile.Write([]byte(content))
	tmpfile.Close()

	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to load YAML config: %v", err)
	}
	if !cfg.HTTPErrorIntel.Enabled {
		t.Error("expected http_error_intel.enabled to default true when omitted from YAML")
	}
	if cfg.HTTPErrorIntel.EnforceMode {
		t.Error("expected http_error_intel.enforce_mode to default false when omitted from YAML")
	}
	if cfg.HTTPErrorIntel.MinBurst != 3 {
		t.Errorf("expected default min_burst 3, got %d", cfg.HTTPErrorIntel.MinBurst)
	}
	if cfg.HTTPErrorIntel.BanThreshold != 20 {
		t.Errorf("expected default ban_threshold 20, got %d", cfg.HTTPErrorIntel.BanThreshold)
	}
}

func TestConfig_HTTPErrorIntel_YAMLOverridesEnforceMode(t *testing.T) {
	os.Setenv("CF_API_TOKEN", "env-token")
	os.Setenv("CF_ZONE_ID", "test-zone")
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")

	content := `
version: v1
http_error_intel:
  enforce_mode: true
  min_burst: 5
  ban_threshold: 50
`
	tmpfile, _ := os.CreateTemp("", "config*.yaml")
	defer os.Remove(tmpfile.Name())
	tmpfile.Write([]byte(content))
	tmpfile.Close()

	cfg, err := Load(tmpfile.Name())
	if err != nil {
		t.Fatalf("failed to load YAML config: %v", err)
	}
	if !cfg.HTTPErrorIntel.Enabled {
		t.Error("expected enabled to remain true (untouched default) when only enforce_mode is set in YAML")
	}
	if !cfg.HTTPErrorIntel.EnforceMode {
		t.Error("expected enforce_mode=true from explicit YAML opt-in")
	}
	if cfg.HTTPErrorIntel.MinBurst != 5 {
		t.Errorf("expected min_burst 5 from YAML, got %d", cfg.HTTPErrorIntel.MinBurst)
	}
	if cfg.HTTPErrorIntel.BanThreshold != 50 {
		t.Errorf("expected ban_threshold 50 from YAML, got %d", cfg.HTTPErrorIntel.BanThreshold)
	}
}

func TestConfig_Validation(t *testing.T) {
	// Cloudflare bootstrap secrets are optional at startup now.
	cfg, err := Load("")
	if err != nil {
		t.Fatalf("expected config to load without Cloudflare bootstrap secrets: %v", err)
	}
	if cfg.Cloudflare.APIToken != "" || cfg.Cloudflare.ZoneID != "" {
		t.Fatalf("expected optional Cloudflare fields to remain empty, got %+v", cfg.Cloudflare)
	}
}

func TestConfig_MaskedString(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "1234567890"

	masked := cfg.MaskedString()
	if !strings.Contains(masked, "1234...7890") {
		t.Errorf("expected masked token in output, got %s", masked)
	}
}

func TestConfig_RuntimeProfileEnvOverride(t *testing.T) {
	os.Setenv("CF_API_TOKEN", "test-token")
	os.Setenv("CF_ZONE_ID", "test-zone")
	os.Setenv("RUNTIME_PROFILE", RuntimeProfileStrictHA)
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")
	defer os.Unsetenv("RUNTIME_PROFILE")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	if cfg.Runtime.Profile != RuntimeProfileStrictHA {
		t.Fatalf("expected strict-ha env override, got %s", cfg.Runtime.Profile)
	}
}

func TestConfig_AbuseIPDBReportingEnabledEnvOverride(t *testing.T) {
	// ABUSEIPDB_REPORTING_ENABLED is no longer honored — feature flags are
	// managed via SQLite ui_settings. Verify the env var is a no-op.
	os.Setenv("CF_API_TOKEN", "test-token")
	os.Setenv("CF_ZONE_ID", "test-zone")
	os.Setenv("ABUSEIPDB_REPORTING_ENABLED", "false")
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")
	defer os.Unsetenv("ABUSEIPDB_REPORTING_ENABLED")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}
	// ReportingEnabled should remain at its default (nil) — not driven by env var.
	if cfg.AbuseIPDB.ReportingEnabled != nil && !*cfg.AbuseIPDB.ReportingEnabled {
		t.Fatalf("ABUSEIPDB_REPORTING_ENABLED must not be honored (use SQLite), got %v", cfg.AbuseIPDB.ReportingEnabled)
	}
}

func TestApplyEnvOverrides_IgnoresEliminatedFlags(t *testing.T) {
	t.Setenv("CLOUDFLARE_MUTATIONS_ENABLED", "1")
	t.Setenv("CS_POLLER_ENABLED", "1")
	t.Setenv("ABUSEIPDB_ENABLED", "1")
	t.Setenv("ABUSEIPDB_REPORTING_ENABLED", "1")

	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	// These env vars must no longer be honored — flags stay at default (false).
	if cfg.Cloudflare.MutationsEnabled {
		t.Error("CLOUDFLARE_MUTATIONS_ENABLED must not be honored (use SQLite)")
	}
	if cfg.CrowdSec.PollerEnabled {
		t.Error("CS_POLLER_ENABLED must not be honored (use SQLite)")
	}
	if cfg.AbuseIPDB.Enabled {
		t.Error("ABUSEIPDB_ENABLED must not be honored (use SQLite)")
	}
}

func TestConfig_RuntimeProfileRejectsUnknownValue(t *testing.T) {
	os.Setenv("CF_API_TOKEN", "test-token")
	os.Setenv("CF_ZONE_ID", "test-zone")
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")

	content := `
version: v1
cloudflare:
  api_token: yaml-token
  zone_id: yaml-zone
runtime:
  profile: mystery
`
	tmpfile, _ := os.CreateTemp("", "config*.yaml")
	defer os.Remove(tmpfile.Name())
	tmpfile.Write([]byte(content))
	tmpfile.Close()

	_, err := Load(tmpfile.Name())
	if err == nil || !strings.Contains(err.Error(), "unsupported runtime profile") {
		t.Fatalf("expected unsupported runtime profile error, got %v", err)
	}
}

func TestResolveAdminToken(t *testing.T) {
	t.Run("file_wins_over_env", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "token*")
		if err != nil {
			t.Fatal(err)
		}
		f.WriteString("file-token\n")
		f.Close()
		t.Setenv("CF_SYNC_API_TOKEN_FILE", f.Name())
		t.Setenv("CF_SYNC_API_TOKEN", "env-token")

		got, err := ResolveAdminToken()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "file-token" {
			t.Errorf("expected file-token, got %q", got)
		}
	})

	t.Run("file_missing_is_error", func(t *testing.T) {
		t.Setenv("CF_SYNC_API_TOKEN_FILE", "/nonexistent/path/token")
		t.Setenv("CF_SYNC_API_TOKEN", "env-token")

		_, err := ResolveAdminToken()
		if err == nil {
			t.Fatal("expected error for missing token file, got nil")
		}
	})

	t.Run("file_empty_is_error", func(t *testing.T) {
		f, err := os.CreateTemp(t.TempDir(), "token*")
		if err != nil {
			t.Fatal(err)
		}
		f.Close()
		t.Setenv("CF_SYNC_API_TOKEN_FILE", f.Name())
		t.Setenv("CF_SYNC_API_TOKEN", "env-token")

		_, err = ResolveAdminToken()
		if err == nil {
			t.Fatal("expected error for empty token file, got nil")
		}
	})

	t.Run("env_fallback", func(t *testing.T) {
		t.Setenv("CF_SYNC_API_TOKEN_FILE", "")
		t.Setenv("CF_SYNC_API_TOKEN", "env-only-token")

		got, err := ResolveAdminToken()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != "env-only-token" {
			t.Errorf("expected env-only-token, got %q", got)
		}
	})

	t.Run("neither_set_is_error", func(t *testing.T) {
		t.Setenv("CF_SYNC_API_TOKEN_FILE", "")
		t.Setenv("CF_SYNC_API_TOKEN", "")

		_, err := ResolveAdminToken()
		if err == nil {
			t.Fatal("expected error when both CF_SYNC_API_TOKEN_FILE and CF_SYNC_API_TOKEN are unset")
		}
	})
}

func TestConfig_GetAdminToken(t *testing.T) {
	t.Run("from memory", func(t *testing.T) {
		cfg := DefaultConfig()
		cfg.Global.AdminToken = "mem-token"
		if got := cfg.GetAdminToken(); got != "mem-token" {
			t.Errorf("expected mem-token, got %s", got)
		}
	})

	t.Run("from file", func(t *testing.T) {
		tmpfile, _ := os.CreateTemp("", "token*")
		defer os.Remove(tmpfile.Name())
		tmpfile.Write([]byte("file-token\n"))
		tmpfile.Close()

		cfg := DefaultConfig()
		cfg.Global.AdminTokenFile = tmpfile.Name()
		if got := cfg.GetAdminToken(); got != "file-token" {
			t.Errorf("expected file-token, got %s", got)
		}
	})

	t.Run("memory overrides file", func(t *testing.T) {
		tmpfile, _ := os.CreateTemp("", "token*")
		defer os.Remove(tmpfile.Name())
		tmpfile.Write([]byte("file-token"))
		tmpfile.Close()

		cfg := DefaultConfig()
		cfg.Global.AdminToken = "mem-token"
		cfg.Global.AdminTokenFile = tmpfile.Name()
		if got := cfg.GetAdminToken(); got != "mem-token" {
			t.Errorf("expected mem-token (override), got %s", got)
		}
	})
}

// TestConfigPrecedenceLayerOrdering proves the configuration hierarchy:
//  1. Built-in defaults (no file, no env)
//  2. YAML config file overrides defaults
//  3. Environment variables override YAML
//
// Note: SQLite/UI-persisted configuration (provider API keys changed via UI)
// is applied by the Server at startup from cfg.UI.ProviderStateFile — it is
// a separate layer above config.Load() and is not tested here.
func TestConfigPrecedenceLayerOrdering(t *testing.T) {
	// Layer 1: Built-in default for log level is "info".
	{
		t.Setenv("CF_API_TOKEN", "tok")
		t.Setenv("CF_ZONE_ID", "zone")
		t.Setenv("RUNTIME_PROFILE", "")
		cfg, err := Load("")
		if err != nil {
			t.Fatalf("defaults load: %v", err)
		}
		if cfg.Global.Log.Level != "info" {
			t.Errorf("layer1 default: expected log level 'info', got %q", cfg.Global.Log.Level)
		}
	}

	// Layer 2: YAML overrides the default log level.
	yamlContent := `
version: v1
global:
  log:
    level: debug
cloudflare:
  api_token: yaml-token
  zone_id: yaml-zone
`
	yamlFile, err := os.CreateTemp(t.TempDir(), "config*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	yamlFile.WriteString(yamlContent)
	yamlFile.Close()

	{
		t.Setenv("CF_API_TOKEN", "tok")
		t.Setenv("CF_ZONE_ID", "zone")
		cfg, err := Load(yamlFile.Name())
		if err != nil {
			t.Fatalf("YAML layer load: %v", err)
		}
		if cfg.Global.Log.Level != "debug" {
			t.Errorf("layer2 YAML: expected log level 'debug', got %q", cfg.Global.Log.Level)
		}
		// Env var overrides YAML for CF token.
		if cfg.Cloudflare.APIToken != "tok" {
			t.Errorf("layer3 env should override YAML token: got %q", cfg.Cloudflare.APIToken)
		}
	}

	// Layer 3: Env var overrides YAML. Use RUNTIME_PROFILE as a clean signal.
	t.Setenv("RUNTIME_PROFILE", RuntimeProfileStrictHA)
	{
		cfg, err := Load(yamlFile.Name())
		if err != nil {
			t.Fatalf("env layer load: %v", err)
		}
		if cfg.Runtime.Profile != RuntimeProfileStrictHA {
			t.Errorf("layer3 env: expected strict-ha runtime profile, got %q", cfg.Runtime.Profile)
		}
		// YAML log level still visible (env only overrides what it sets).
		if cfg.Global.Log.Level != "debug" {
			t.Errorf("layer3 env: YAML log level should be preserved, got %q", cfg.Global.Log.Level)
		}
	}
}

func TestProtectedHostsFromEnvVar(t *testing.T) {
	t.Setenv("SECURITY_AUTOMATION_PROTECTED_HOSTS", "82.65.145.189, 10.0.0.1, ")
	cfg := DefaultConfig()
	applyEnvOverrides(cfg)

	want := []string{"82.65.145.189", "10.0.0.1"}
	if len(cfg.Global.ProtectedHosts) != len(want) {
		t.Fatalf("expected %d protected hosts, got %d: %v", len(want), len(cfg.Global.ProtectedHosts), cfg.Global.ProtectedHosts)
	}
	for i, h := range want {
		if cfg.Global.ProtectedHosts[i] != h {
			t.Errorf("host[%d]: want %q, got %q", i, h, cfg.Global.ProtectedHosts[i])
		}
	}
}

func TestProtectedHostsFromYAML(t *testing.T) {
	yamlContent := `
version: v1
global:
  protected_hosts:
    - 82.65.145.189
    - 192.168.100.0/24
`
	f, err := os.CreateTemp("", "config-*.yaml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(yamlContent); err != nil {
		t.Fatalf("write config: %v", err)
	}
	f.Close()

	cfg, err := Load(f.Name())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cfg.Global.ProtectedHosts) != 2 {
		t.Fatalf("expected 2 protected hosts from YAML, got %d: %v", len(cfg.Global.ProtectedHosts), cfg.Global.ProtectedHosts)
	}
	if cfg.Global.ProtectedHosts[0] != "82.65.145.189" {
		t.Errorf("host[0]: want 82.65.145.189, got %q", cfg.Global.ProtectedHosts[0])
	}
	if cfg.Global.ProtectedHosts[1] != "192.168.100.0/24" {
		t.Errorf("host[1]: want 192.168.100.0/24, got %q", cfg.Global.ProtectedHosts[1])
	}
}
