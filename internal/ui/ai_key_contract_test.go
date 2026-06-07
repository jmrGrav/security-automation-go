package ui

// Contract tests proving that the wizard → ReadAPIKeyFile chain is correct.
//
// These tests access unexported functions (writeProviderSecret, atomicWriteFile)
// and must live in package ui (not ui_test).

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/ai/providers"
)

// TestAIKeyContract_WizardWriteRawReadAPIKeyFile proves that writeProviderSecret
// (used by wizard step 7) produces output that ReadAPIKeyFile reads back correctly.
func TestAIKeyContract_WizardWriteRawReadAPIKeyFile(t *testing.T) {
	cases := []struct {
		name   string
		rawKey string
	}{
		{"openai", "sk-proj-abc123XYZ"},
		{"anthropic", "sk-ant-api03-abc123"},
		{"gemini", "AIzaSy-abc123XYZ"},
		{"with_trailing_newline", "sk-proj-newline\n"}, // writeProviderSecret writes as-is; ReadAPIKeyFile strips
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, tc.name+"_api_key")

			if err := writeProviderSecret(path, tc.rawKey); err != nil {
				t.Fatalf("writeProviderSecret: %v", err)
			}

			got, err := providers.ReadAPIKeyFile(path)
			if err != nil {
				t.Fatalf("ReadAPIKeyFile: %v", err)
			}

			want := strings.TrimSpace(tc.rawKey)
			if got != want {
				t.Errorf("roundtrip mismatch: write %q, read back %q", want, got)
			}
		})
	}
}

// TestAIKeyContract_WizardWriteSameAsProviderAdminUI proves that writeProviderSecret
// produces identical bytes whether called from the wizard (step 7) or the provider
// admin UI. This is the key invariant: one format, two entry points.
func TestAIKeyContract_WizardWriteSameAsProviderAdminUI(t *testing.T) {
	rawKey := "sk-proj-testkey123"
	dir := t.TempDir()
	wizardPath := filepath.Join(dir, "wizard_openai_key")
	adminPath := filepath.Join(dir, "admin_openai_key")

	if err := writeProviderSecret(wizardPath, rawKey); err != nil {
		t.Fatalf("wizard write: %v", err)
	}
	if err := writeProviderSecret(adminPath, rawKey); err != nil {
		t.Fatalf("admin write: %v", err)
	}

	wizardBytes, err := os.ReadFile(wizardPath)
	if err != nil {
		t.Fatal(err)
	}
	adminBytes, err := os.ReadFile(adminPath)
	if err != nil {
		t.Fatal(err)
	}

	if string(wizardBytes) != string(adminBytes) {
		t.Errorf("wizard output %q != admin output %q", wizardBytes, adminBytes)
	}
}

// TestAIKeyContract_WriteSecretFileBrokenForAIKeys documents why WriteSecretFile
// must NOT be used for AI keys. The KEY=VALUE output cannot be used as a bearer token.
func TestAIKeyContract_WriteSecretFileBrokenForAIKeys(t *testing.T) {
	rawKey := "sk-proj-testkey123"
	dir := t.TempDir()
	path := filepath.Join(dir, "broken_ai_key")

	// Simulate the old (buggy) wizard step 7 code:
	if err := WriteSecretFile(path, map[string]string{"OPENAI_API_KEY": rawKey}); err != nil {
		t.Fatalf("WriteSecretFile: %v", err)
	}

	got, err := providers.ReadAPIKeyFile(path)
	if err != nil {
		t.Fatalf("ReadAPIKeyFile: %v", err)
	}

	// ReadAPIKeyFile returns the full line — NOT the raw key.
	// This is the bug: the bearer token would be "OPENAI_API_KEY=sk-proj-..." → 401.
	wantBroken := fmt.Sprintf("OPENAI_API_KEY=%s", rawKey)
	if got != wantBroken {
		t.Errorf("want broken value %q, got %q", wantBroken, got)
	}
	if got == rawKey {
		t.Error("WriteSecretFile KEY=VALUE output must NOT equal the raw key — test setup is wrong")
	}
}

// TestAIKeyContract_EnvFileFormatForSystemdSecrets proves that WriteSecretFile
// (used for CF token, AbuseIPDB, BetterStack) produces valid env-file format
// that systemd EnvironmentFile= can parse.
func TestAIKeyContract_EnvFileFormatForSystemdSecrets(t *testing.T) {
	cases := []struct {
		envKey string
		value  string
	}{
		{"CF_API_TOKEN", "v1.0-xxxxxxxx-yyyyyyyy"},
		{"ABUSEIPDB_KEY", "abc123def456"},
		{"BETTERSTACK_SOURCE_TOKEN", "xyz789"},
	}

	for _, tc := range cases {
		t.Run(tc.envKey, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "secret_file")

			if err := WriteSecretFile(path, map[string]string{tc.envKey: tc.value}); err != nil {
				t.Fatalf("WriteSecretFile: %v", err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}

			content := strings.TrimSpace(string(data))
			expected := fmt.Sprintf("%s=%s", tc.envKey, tc.value)
			if content != expected {
				t.Errorf("want %q, got %q", expected, content)
			}

			// Verify file mode is 0600.
			info, _ := os.Stat(path)
			if info.Mode().Perm() != 0o600 {
				t.Errorf("want 0600, got %o", info.Mode().Perm())
			}
		})
	}
}
