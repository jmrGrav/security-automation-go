package config

import (
	"testing"
	"time"
)

func TestConfig_UIAndProviderEnvOverrides(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test-token")
	t.Setenv("CF_ZONE_ID", "test-zone")
	t.Setenv("UI_ENABLED", "1")
	t.Setenv("UI_ADDR", "127.0.0.1:9090")
	t.Setenv("UI_MUTATIONS_ENABLED", "0")
	t.Setenv("UI_SECRET_FILE", "/var/lib/cf-sync/secrets.local")
	t.Setenv("ENRICHMENT_ENABLED", "1")
	t.Setenv("ENRICHMENT_DNS_ENABLED", "1")
	t.Setenv("ENRICHMENT_ASN_ENABLED", "1")
	t.Setenv("ENRICHMENT_TIMEOUT_MS", "800")
	t.Setenv("ENRICHMENT_CACHE_TTL", "6h")
	t.Setenv("ABUSEIPDB_ENABLED", "1")
	t.Setenv("SPAMHAUS_ENABLED", "1")
	t.Setenv("VIRUSTOTAL_ENABLED", "1")
	t.Setenv("CLOUDFLARE_MUTATIONS_ENABLED", "0")
	t.Setenv("SPAMHAUS_API_KEY", "spamhaus-key")
	t.Setenv("VIRUSTOTAL_API_KEY", "virustotal-key")
	t.Setenv("ABUSEIPDB_KEY", "abuse-key")

	cfg, err := Load("")
	if err != nil {
		t.Fatalf("Load() failed: %v", err)
	}

	if !cfg.UI.Enabled || cfg.UI.Addr != "127.0.0.1:9090" || cfg.UI.MutationsEnabled {
		t.Fatalf("unexpected UI config: %+v", cfg.UI)
	}
	if cfg.UI.SecretFile != "/var/lib/cf-sync/secrets.local" {
		t.Fatalf("unexpected UI secret file: %s", cfg.UI.SecretFile)
	}
	if !cfg.Enrichment.Enabled || !cfg.Enrichment.DNSEnabled || !cfg.Enrichment.ASNEnabled {
		t.Fatalf("unexpected enrichment config: %+v", cfg.Enrichment)
	}
	if cfg.Enrichment.Timeout != 800*time.Millisecond {
		t.Fatalf("unexpected enrichment timeout: %s", cfg.Enrichment.Timeout)
	}
	if cfg.Enrichment.CacheTTL != 6*time.Hour {
		t.Fatalf("unexpected enrichment cache ttl: %s", cfg.Enrichment.CacheTTL)
	}
	if !cfg.AbuseIPDB.Enabled || !cfg.Spamhaus.Enabled || !cfg.VirusTotal.Enabled {
		t.Fatalf("unexpected provider toggles: abuse=%t spamhaus=%t virustotal=%t", cfg.AbuseIPDB.Enabled, cfg.Spamhaus.Enabled, cfg.VirusTotal.Enabled)
	}
	if cfg.Cloudflare.MutationsEnabled {
		t.Fatalf("expected Cloudflare mutations to be disabled by env override")
	}
	if cfg.AbuseIPDB.APIKey != "abuse-key" {
		t.Fatalf("unexpected AbuseIPDB key mapping")
	}
	if cfg.Spamhaus.APIKey != "spamhaus-key" {
		t.Fatalf("unexpected Spamhaus key mapping")
	}
	if cfg.VirusTotal.APIKey != "virustotal-key" {
		t.Fatalf("unexpected VirusTotal key mapping")
	}
}

func TestConfig_MaskedString_RedactsProviderSecrets(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Cloudflare.APIToken = "super-secret-token-12345"
	cfg.AbuseIPDB.APIKey = "abuse-secret"
	cfg.Spamhaus.APIKey = "spamhaus-secret"
	cfg.VirusTotal.APIKey = "virustotal-secret"

	masked := cfg.MaskedString()
	for _, secret := range []string{"super-secret-token-12345", "abuse-secret", "spamhaus-secret", "virustotal-secret"} {
		if secret == "" {
			continue
		}
		if contains(masked, secret) {
			t.Fatalf("masked config leaked secret %q: %s", secret, masked)
		}
	}
}

func TestConfig_UIEnabledRequiresAddr(t *testing.T) {
	t.Setenv("CF_API_TOKEN", "test-token")
	t.Setenv("CF_ZONE_ID", "test-zone")

	cfg := DefaultConfig()
	cfg.UI.Enabled = true
	cfg.UI.Addr = ""
	if err := validate(cfg); err == nil {
		t.Fatal("expected UI-enabled config with empty addr to fail")
	}
}

func TestConfig_DefaultsKeepUIReadOnly(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.UI.Enabled {
		t.Fatal("UI must default to disabled")
	}
	if cfg.UI.MutationsEnabled {
		t.Fatal("UI mutations must default to disabled")
	}
	if cfg.Cloudflare.MutationsEnabled {
		t.Fatal("Cloudflare mutations must default to disabled")
	}
	if !cfg.Enrichment.Enabled || !cfg.Enrichment.DNSEnabled || !cfg.Enrichment.ASNEnabled {
		t.Fatalf("enrichment defaults should be enabled: %+v", cfg.Enrichment)
	}
	if cfg.Enrichment.Timeout != 800*time.Millisecond || cfg.Enrichment.CacheTTL != 6*time.Hour {
		t.Fatalf("unexpected enrichment defaults: %+v", cfg.Enrichment)
	}
}

func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) && (stringIndex(s, substr) >= 0)
}

func stringIndex(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
