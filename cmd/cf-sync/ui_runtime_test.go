package main

import (
	"bytes"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ai "github.com/jm/security-automation-go/internal/ai"
	"github.com/jm/security-automation-go/internal/ai/providers"
	"github.com/jm/security-automation-go/internal/ai/providers/anthropic"
	"github.com/jm/security-automation-go/internal/ai/providers/gemini"
	"github.com/jm/security-automation-go/internal/ai/providers/openai"
)

func TestBuildAIProvidersReturnsNothingWhenDisabled(t *testing.T) {
	got := buildAIProviders(ai.Config{}, nil)
	if len(got) != 0 {
		t.Fatalf("expected no providers when disabled, got %d", len(got))
	}
}

func TestBuildAIProvidersActivatesConfiguredProvider(t *testing.T) {
	cases := []struct {
		name string
		cfg  ai.Config
		want providers.Name
	}{
		{
			name: "openai",
			cfg: ai.Config{
				Enabled: true,
				OpenAI: ai.ProviderConfig{
					Enabled:    true,
					Model:      "gpt-4.1-mini",
					APIKeyFile: writeKeyFile(t, "test-openai-key"),
				},
			},
			want: providers.OpenAI,
		},
		{
			name: "anthropic",
			cfg: ai.Config{
				Enabled: true,
				Anthropic: ai.ProviderConfig{
					Enabled:    true,
					Model:      "claude-3-5-sonnet-latest",
					APIKeyFile: writeKeyFile(t, "test-anthropic-key"),
				},
			},
			want: providers.Anthropic,
		},
		{
			name: "gemini",
			cfg: ai.Config{
				Enabled: true,
				Gemini: ai.ProviderConfig{
					Enabled:    true,
					Model:      "gemini-1.5-pro",
					APIKeyFile: writeKeyFile(t, "test-gemini-key"),
				},
			},
			want: providers.Gemini,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := buildAIProviders(tc.cfg, nil)
			if len(got) != 1 {
				t.Fatalf("expected one provider, got %d", len(got))
			}
			if got[0].Name() != tc.want {
				t.Fatalf("expected provider %q, got %q", tc.want, got[0].Name())
			}
			if enabler, ok := got[0].(interface{ Enabled() bool }); !ok || !enabler.Enabled() {
				t.Fatalf("expected provider %q to be enabled", tc.want)
			}
		})
	}
}

func TestBuildAIProvidersSkipsUnreadableSecretAndRedactsLogs(t *testing.T) {
	dir := t.TempDir()
	secretFile := filepath.Join(dir, "openai_api_key")
	if err := os.WriteFile(secretFile, []byte("super-secret-token"), 0o644); err != nil {
		t.Fatalf("write secret file: %v", err)
	}

	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
	got := buildAIProviders(ai.Config{
		Enabled: true,
		OpenAI: ai.ProviderConfig{
			Enabled:    true,
			Model:      "gpt-4.1-mini",
			APIKeyFile: secretFile,
		},
	}, logger)
	if len(got) != 0 {
		t.Fatalf("expected unreadable secret to keep provider unavailable, got %d providers", len(got))
	}
	out := buf.String()
	if !strings.Contains(out, "openai") {
		t.Fatalf("expected warning to mention provider name, got %q", out)
	}
	if strings.Contains(out, "super-secret-token") {
		t.Fatalf("logger leaked secret content: %q", out)
	}
}

func writeKeyFile(t *testing.T, secret string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "api-key.txt")
	if err := os.WriteFile(path, []byte(secret), 0o600); err != nil {
		t.Fatalf("write key file: %v", err)
	}
	return path
}

var _ = anthropic.New
var _ = gemini.New
var _ = openai.New
