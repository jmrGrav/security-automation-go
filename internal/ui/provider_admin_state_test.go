package ui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	ai "github.com/jm/security-automation-go/internal/ai"
)

func TestAIProviderStateRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ai-providers.env")
	state := AIProviderState{
		OpenAI: AIProviderRecord{
			Enabled:           true,
			Model:             "gpt-4.1-mini",
			LastTestAt:        time.Date(2026, 6, 2, 10, 11, 12, 0, time.UTC),
			LastTestStatus:    "READY",
			LastTestLatencyMS: 123,
			LastErrorCode:     "",
		},
		Anthropic: AIProviderRecord{
			Enabled:           false,
			Model:             "claude-3-5-sonnet-latest",
			LastTestStatus:    "TIMEOUT",
			LastTestLatencyMS: 456,
			LastErrorCode:     "TIMEOUT",
		},
	}

	if err := saveAIProviderState(path, state); err != nil {
		t.Fatalf("save state: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read state: %v", err)
	}
	for _, forbidden := range []string{"sk-", "secret", "token", "prompt"} {
		if strings.Contains(strings.ToLower(string(raw)), forbidden) {
			t.Fatalf("state file leaked %q: %s", forbidden, string(raw))
		}
	}
	for _, want := range []string{
		"OPENAI_ENABLED=true",
		"OPENAI_MODEL=gpt-4.1-mini",
		"ANTHROPIC_ENABLED=false",
		"ANTHROPIC_MODEL=claude-3-5-sonnet-latest",
	} {
		if !strings.Contains(string(raw), want) {
			t.Fatalf("expected canonical state key %q in %s", want, string(raw))
		}
	}
	if strings.Contains(string(raw), "AI_PROVIDER_OPENAI_ENABLED") || strings.Contains(string(raw), "AI_PROVIDER_ANTHROPIC_ENABLED") {
		t.Fatalf("state file should use canonical keys without AI_PROVIDER prefix: %s", string(raw))
	}

	loaded, ok, err := loadAIProviderState(path)
	if err != nil {
		t.Fatalf("load state: %v", err)
	}
	if !ok {
		t.Fatal("expected state file to be present")
	}
	if loaded.OpenAI.Model != state.OpenAI.Model || !loaded.OpenAI.Enabled || loaded.OpenAI.LastTestStatus != "READY" || loaded.OpenAI.LastTestLatencyMS != 123 {
		t.Fatalf("round-trip mismatch for openai: %#v", loaded.OpenAI)
	}
	if loaded.Anthropic.Model != state.Anthropic.Model || loaded.Anthropic.Enabled || loaded.Anthropic.LastErrorCode != "TIMEOUT" {
		t.Fatalf("round-trip mismatch for anthropic: %#v", loaded.Anthropic)
	}
}

func TestAtomicWriteFileSetsPermissionsAndDoesNotLeaveTempFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openai_api_key")

	if err := atomicWriteFile(path, []byte("secret-value"), 0o600, -1, -1); err != nil {
		t.Fatalf("atomic write failed: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat secret file: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected 0600 permissions, got %#o", got)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read secret file: %v", err)
	}
	if string(data) != "secret-value" {
		t.Fatalf("unexpected secret file contents: %q", string(data))
	}
	if matches, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(matches) != 0 {
		t.Fatalf("expected no temp files left behind, got %v", matches)
	}
}

func TestProviderManagementEntry_DisabledNoKeyShowsNotConfigured(t *testing.T) {
	entry := providerManagementEntry(
		AIProviderOpenAI,
		ai.ProviderConfig{Model: "gpt-4.1-mini"},
		false,
		AIProviderRecord{Enabled: false},
	)

	if entry.Status != providerStatusDisabled {
		t.Fatalf("expected disabled status, got %q", entry.Status)
	}
	if entry.SecretState != "not configured" {
		t.Fatalf("expected not configured secret state, got %q", entry.SecretState)
	}
	if entry.ValidationMessage != "provider disabled by operator" {
		t.Fatalf("expected provider disabled by operator, got %q", entry.ValidationMessage)
	}
}

func TestProviderManagementEntry_EnabledNoKeyShowsMissingSecret(t *testing.T) {
	entry := providerManagementEntry(
		AIProviderOpenAI,
		ai.ProviderConfig{Enabled: true, Model: "gpt-4.1-mini"},
		false,
		AIProviderRecord{Enabled: true},
	)

	if entry.Status != providerStatusMissingSecret {
		t.Fatalf("expected missing secret status, got %q", entry.Status)
	}
	if entry.SecretState != providerStatusMissingSecret {
		t.Fatalf("expected missing secret state, got %q", entry.SecretState)
	}
	if entry.ValidationMessage != "credential missing from SQLite" {
		t.Fatalf("expected credential missing validation message, got %q", entry.ValidationMessage)
	}
}

func TestProviderManagementEntry_ConfiguredButDisabledStaysConfigured(t *testing.T) {
	entry := providerManagementEntry(
		AIProviderOpenAI,
		ai.ProviderConfig{Model: "gpt-4.1-mini"},
		true,
		AIProviderRecord{Enabled: false},
	)

	if entry.Status != providerStatusDisabled {
		t.Fatalf("expected disabled status, got %q", entry.Status)
	}
	if entry.SecretState != "configured" {
		t.Fatalf("expected configured secret state, got %q", entry.SecretState)
	}
	if entry.ValidationMessage != "provider disabled by operator" {
		t.Fatalf("expected provider disabled by operator, got %q", entry.ValidationMessage)
	}
}
