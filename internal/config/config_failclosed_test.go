package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestValidate_OptionalCloudflareSecretsAllowFreshInstall verifies that the
// bootstrap config can start without Cloudflare credentials; production enable
// is still gated elsewhere.
func TestValidate_MissingToken_AllowsFreshInstall(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = ""
	cfg.Cloudflare.ZoneID = "z"
	if err := validate(cfg); err != nil {
		t.Fatalf("bootstrap config should allow missing Cloudflare token: %v", err)
	}
}

func TestValidate_MissingZoneID_AllowsFreshInstall(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "tok"
	cfg.Cloudflare.ZoneID = ""
	if err := validate(cfg); err != nil {
		t.Fatalf("bootstrap config should allow missing Cloudflare zone ID: %v", err)
	}
}

func TestValidate_ZeroInterval_FailClosed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "tok"
	cfg.Cloudflare.ZoneID = "z"
	cfg.Interval = 0
	if err := validate(cfg); err == nil {
		t.Error("zero interval must be rejected")
	}
}

func TestValidate_NegativeInterval_FailClosed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "tok"
	cfg.Cloudflare.ZoneID = "z"
	cfg.Interval = -1 * time.Second
	if err := validate(cfg); err == nil {
		t.Error("negative interval must be rejected")
	}
}

func TestValidate_UnknownRuntimeProfile_FailClosed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "tok"
	cfg.Cloudflare.ZoneID = "z"
	cfg.Runtime.Profile = "unknown-profile"
	if err := validate(cfg); err == nil {
		t.Error("unknown runtime profile must be rejected")
	} else if !strings.Contains(err.Error(), "allowed") {
		t.Fatalf("unknown profile error should mention allowed values, got %v", err)
	}
}

func TestValidate_SchemaVersionMismatch_FailClosed(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "tok"
	cfg.Cloudflare.ZoneID = "z"
	cfg.Version = "v99"
	if err := validate(cfg); err == nil {
		t.Error("wrong schema version must be rejected")
	}
}

// TestLoad_MalformedYAML verifies that a config file with YAML syntax errors
// returns an error and does not return a partially-loaded config.
func TestLoad_MalformedYAML(t *testing.T) {
	f, err := os.CreateTemp("", "bad*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(f.Name())
	f.WriteString(`version: v1
cloudflare:
  api_token: [invalid yaml here`)
	f.Close()

	_, err = Load(f.Name())
	if err == nil {
		t.Error("malformed YAML must return an error")
	}
	if !strings.Contains(err.Error(), f.Name()) {
		t.Fatalf("malformed YAML error should mention file path, got %v", err)
	}
}

// TestLoad_FileNotFound verifies a missing config file path returns an error.
func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/to/config.yaml")
	if err == nil {
		t.Error("missing config file must return error")
	}
	if !strings.Contains(err.Error(), "/nonexistent/path/to/config.yaml") {
		t.Fatalf("missing file error should mention path, got %v", err)
	}
}

// TestMaskedString_RedactsSecrets verifies that sensitive values are never
// logged verbatim. This is a security regression test.
func TestMaskedString_RedactsSecrets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "super-secret-token-12345"
	cfg.Cloudflare.ZoneID = "my-zone-id"

	masked := cfg.MaskedString()

	if strings.Contains(masked, "super-secret-token-12345") {
		t.Error("SECURITY: CF API token must be redacted in MaskedString()")
	}
	// Zone ID can appear (not a secret), but the token must not
}

// TestLoad_EnvOverrides_Precedence verifies that environment variables override
// YAML values, which override defaults.
func TestLoad_EnvOverrides_Precedence(t *testing.T) {
	os.Setenv("CF_API_TOKEN", "env-token")
	os.Setenv("CF_ZONE_ID", "env-zone")
	os.Setenv("STATE_DIR", "/tmp/test-state")
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")
	defer os.Unsetenv("STATE_DIR")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.Cloudflare.APIToken != "env-token" {
		t.Errorf("env CF_API_TOKEN must override default; got %q", cfg.Cloudflare.APIToken)
	}
	if cfg.StateDir != "/tmp/test-state" {
		t.Errorf("env STATE_DIR must override default; got %q", cfg.StateDir)
	}
}

// TestLoad_ValidProfiles verifies that both accepted runtime profiles pass validation.
func TestLoad_ValidProfiles(t *testing.T) {
	os.Setenv("CF_API_TOKEN", "tok")
	os.Setenv("CF_ZONE_ID", "z")
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")

	for _, profile := range []string{RuntimeProfileSingleNode, RuntimeProfileStrictHA} {
		os.Setenv("RUNTIME_PROFILE", profile)
		defer os.Unsetenv("RUNTIME_PROFILE")

		cfg, err := Load("")
		if err != nil {
			t.Errorf("profile %q should be valid: %v", profile, err)
		}
		if cfg.Runtime.Profile != profile {
			t.Errorf("profile not set: want %q, got %q", profile, cfg.Runtime.Profile)
		}
	}
}

// TestCrowdSecConfig_Defaults verifies cscli defaults are applied.
func TestCrowdSecConfig_Defaults(t *testing.T) {
	os.Setenv("CF_API_TOKEN", "tok")
	os.Setenv("CF_ZONE_ID", "z")
	defer os.Unsetenv("CF_API_TOKEN")
	defer os.Unsetenv("CF_ZONE_ID")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.CrowdSec.BinPath != "cscli" {
		t.Errorf("default BinPath must be 'cscli', got %q", cfg.CrowdSec.BinPath)
	}
	if cfg.CrowdSec.Timeout != 15*time.Second {
		t.Errorf("default Timeout must be 15s, got %v", cfg.CrowdSec.Timeout)
	}
	if cfg.CrowdSec.AllowlistName != "my_allowlist" {
		t.Errorf("default AllowlistName must be 'my_allowlist', got %q", cfg.CrowdSec.AllowlistName)
	}
}
