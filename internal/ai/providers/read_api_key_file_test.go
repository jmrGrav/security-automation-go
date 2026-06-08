package providers_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jm/security-automation-go/internal/ai/providers"
)

// TestReadAPIKeyFile_RawValue covers the legacy import helper only.
// Runtime credential lookup does not call ReadAPIKeyFile.
func TestReadAPIKeyFile_RawValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openai_api_key")
	rawKey := "sk-proj-abc123XYZ"
	if err := os.WriteFile(path, []byte(rawKey+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := providers.ReadAPIKeyFile(path)
	if err != nil {
		t.Fatalf("ReadAPIKeyFile error: %v", err)
	}
	if got != rawKey {
		t.Errorf("want %q, got %q", rawKey, got)
	}
}

// TestReadAPIKeyFile_KeyValueFormatReturnsWrongValue documents why KEY=VALUE is
// not suitable for raw API keys in the legacy import path.
func TestReadAPIKeyFile_KeyValueFormatReturnsWrongValue(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "openai_api_key")
	rawKey := "sk-proj-abc123"
	// Simulate old env-file style output used by legacy imports.
	content := "OPENAI_API_KEY=" + rawKey
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := providers.ReadAPIKeyFile(path)
	if err != nil {
		t.Fatalf("ReadAPIKeyFile error: %v", err)
	}
	// ReadAPIKeyFile returns the full string including the prefix — NOT the raw key.
	// This is the bug: "Bearer OPENAI_API_KEY=sk-..." would be sent to the provider API.
	if got == rawKey {
		t.Error("test setup incorrect: KEY=VALUE format should NOT equal the raw key")
	}
	if got != content {
		t.Errorf("want %q (full line), got %q", content, got)
	}
}

// TestReadAPIKeyFile_EmptyFileFails verifies that the legacy helper rejects empty files.
func TestReadAPIKeyFile_EmptyFileFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "empty_key")
	if err := os.WriteFile(path, []byte("   \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := providers.ReadAPIKeyFile(path)
	if err == nil {
		t.Error("expected error for empty/whitespace-only file")
	}
}

// TestReadAPIKeyFile_WorldReadableFails verifies that the legacy helper rejects loose permissions.
func TestReadAPIKeyFile_WorldReadableFails(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "loose_key")
	if err := os.WriteFile(path, []byte("sk-abc"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := providers.ReadAPIKeyFile(path)
	if err == nil {
		t.Error("expected error for world-readable file (0644)")
	}
}

// TestReadAPIKeyFile_MissingFileFails verifies that a missing legacy file returns an error.
func TestReadAPIKeyFile_MissingFileFails(t *testing.T) {
	_, err := providers.ReadAPIKeyFile("/tmp/nonexistent-key-file-xyz987")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

// TestReadAPIKeyFile_UnconfiguredFails verifies that an empty path is rejected for the legacy helper.
func TestReadAPIKeyFile_UnconfiguredFails(t *testing.T) {
	_, err := providers.ReadAPIKeyFile("")
	if err == nil {
		t.Error("expected error for empty path")
	}
}
