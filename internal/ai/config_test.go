package ai

import "testing"

func TestFromEnvDefaultsKeepProvidersDisabled(t *testing.T) {
	t.Setenv("AI_PROVIDER_OPENAI_ENABLED", "")
	t.Setenv("AI_PROVIDER_ANTHROPIC_ENABLED", "")
	t.Setenv("AI_PROVIDER_GEMINI_ENABLED", "")

	cfg := FromEnv()
	if cfg.OpenAI.Enabled || cfg.Anthropic.Enabled || cfg.Gemini.Enabled {
		t.Fatalf("expected providers to remain disabled by default: %+v", cfg)
	}
	if cfg.OpenAI.APIKeyFile != "" || cfg.Anthropic.APIKeyFile != "" || cfg.Gemini.APIKeyFile != "" {
		t.Fatalf("expected file-backed provider paths to default empty: %+v", cfg)
	}
}

func TestFromEnvIgnoresFileBackedProviderEnvVars(t *testing.T) {
	tempPath := t.TempDir() + "/openai_api_key"
	t.Setenv("AI_PROVIDER_OPENAI_ENABLED", "true")
	t.Setenv("AI_PROVIDER_OPENAI_MODEL", "gpt-4.1-mini")
	t.Setenv("AI_PROVIDER_OPENAI_API_KEY_FILE", tempPath)
	t.Setenv("AI_PROVIDER_ANTHROPIC_ENABLED", "true")
	t.Setenv("AI_PROVIDER_ANTHROPIC_MODEL", "claude-3-5-sonnet-latest")
	t.Setenv("AI_PROVIDER_ANTHROPIC_API_KEY_FILE", t.TempDir()+"/anthropic_api_key")
	t.Setenv("AI_PROVIDER_GEMINI_ENABLED", "true")
	t.Setenv("AI_PROVIDER_GEMINI_MODEL", "gemini-1.5-pro")
	t.Setenv("AI_PROVIDER_GEMINI_API_KEY_FILE", t.TempDir()+"/gemini_api_key")

	cfg := FromEnv()
	if !cfg.OpenAI.Enabled || cfg.OpenAI.Model != "gpt-4.1-mini" || cfg.OpenAI.APIKeyFile != "" {
		t.Fatalf("unexpected openai config: %+v", cfg.OpenAI)
	}
	if !cfg.Anthropic.Enabled || cfg.Anthropic.Model != "claude-3-5-sonnet-latest" || cfg.Anthropic.APIKeyFile != "" {
		t.Fatalf("unexpected anthropic config: %+v", cfg.Anthropic)
	}
	if !cfg.Gemini.Enabled || cfg.Gemini.Model != "gemini-1.5-pro" || cfg.Gemini.APIKeyFile != "" {
		t.Fatalf("unexpected gemini config: %+v", cfg.Gemini)
	}
}

func TestFromEnvIgnoresRawProviderTokenEnvVars(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "super-secret-openai")
	t.Setenv("ANTHROPIC_API_KEY", "super-secret-anthropic")
	t.Setenv("GEMINI_API_KEY", "super-secret-gemini")

	cfg := FromEnv()
	if cfg.OpenAI.APIKeyFile != "" || cfg.Anthropic.APIKeyFile != "" || cfg.Gemini.APIKeyFile != "" {
		t.Fatalf("expected raw provider keys to be ignored: %+v", cfg)
	}
}
