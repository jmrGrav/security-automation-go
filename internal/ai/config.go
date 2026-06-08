package ai

import (
	"os"
	"strconv"
	"time"
)

// ProviderConfig reserves future provider-specific settings without wiring calls.
type ProviderConfig struct {
	Enabled bool
	Model   string
	APIKey  string
	// APIKeyFile is kept only for legacy import/test compatibility.
	// Runtime credential lookup uses encrypted SQLite CredentialStore.
	APIKeyFile string
}

// Config controls the explain-only AI gateway.
type Config struct {
	Enabled            bool
	ProviderStrategy   string
	MaxContextBytes    int
	MaxOutputTokens    int
	Timeout            time.Duration
	RateLimitPerMinute int
	CacheTTL           time.Duration
	StrictNoTools      bool
	OpenAI             ProviderConfig
	Anthropic          ProviderConfig
	Gemini             ProviderConfig
}

// FromEnv returns the fail-closed AI config derived from environment variables.
func FromEnv() Config {
	cfg := Config{
		Enabled:            envBool("AI_EXPLAIN_ENABLED", false),
		ProviderStrategy:   envString("AI_EXPLAIN_PROVIDER_STRATEGY", "auto"),
		MaxContextBytes:    envInt("AI_EXPLAIN_MAX_CONTEXT_BYTES", 12000),
		MaxOutputTokens:    envInt("AI_EXPLAIN_MAX_OUTPUT_TOKENS", 800),
		Timeout:            envDuration("AI_EXPLAIN_TIMEOUT", 15*time.Second),
		RateLimitPerMinute: envInt("AI_EXPLAIN_RATE_LIMIT_PER_MINUTE", 10),
		CacheTTL:           envDuration("AI_EXPLAIN_CACHE_TTL", 15*time.Minute),
		StrictNoTools:      envBool("AI_EXPLAIN_STRICT_NO_TOOLS", true),
		OpenAI: ProviderConfig{
			Enabled:    envBool("AI_PROVIDER_OPENAI_ENABLED", false),
			Model:      envString("AI_PROVIDER_OPENAI_MODEL", ""),
			APIKey:     "",
			APIKeyFile: "",
		},
		Anthropic: ProviderConfig{
			Enabled:    envBool("AI_PROVIDER_ANTHROPIC_ENABLED", false),
			Model:      envString("AI_PROVIDER_ANTHROPIC_MODEL", ""),
			APIKey:     "",
			APIKeyFile: "",
		},
		Gemini: ProviderConfig{
			Enabled:    envBool("AI_PROVIDER_GEMINI_ENABLED", false),
			Model:      envString("AI_PROVIDER_GEMINI_MODEL", ""),
			APIKey:     "",
			APIKeyFile: "",
		},
	}
	if cfg.MaxContextBytes <= 0 {
		cfg.MaxContextBytes = 12000
	}
	if cfg.MaxOutputTokens <= 0 {
		cfg.MaxOutputTokens = 800
	}
	if cfg.RateLimitPerMinute <= 0 {
		cfg.RateLimitPerMinute = 10
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = 15 * time.Minute
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 15 * time.Second
	}
	return cfg
}

func envString(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

func envBool(name string, fallback bool) bool {
	if v := os.Getenv(name); v != "" {
		if parsed, err := strconv.ParseBool(v); err == nil {
			return parsed
		}
	}
	return fallback
}

func envInt(name string, fallback int) int {
	if v := os.Getenv(name); v != "" {
		if parsed, err := strconv.Atoi(v); err == nil {
			return parsed
		}
	}
	return fallback
}

func envDuration(name string, fallback time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			return parsed
		}
	}
	return fallback
}
