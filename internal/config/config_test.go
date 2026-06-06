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

func TestConfig_Validation(t *testing.T) {
	os.Unsetenv("CF_API_TOKEN")
	os.Unsetenv("CF_ZONE_ID")

	_, err := Load("")
	if err == nil {
		t.Error("expected error when missing required fields")
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
	if cfg.AbuseIPDB.ReportingEnabled == nil || *cfg.AbuseIPDB.ReportingEnabled {
		t.Fatalf("expected abuseipdb reporting disabled env override, got %v", cfg.AbuseIPDB.ReportingEnabled)
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
