package ui

import (
	"os"
	"path/filepath"
	"testing"
)

// FileSecretProvider remains for UI bootstrap/session-secret handling only.
func TestWriteSecretFile_Uses0600Permissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "secrets.local")

	if err := WriteSecretFile(path, map[string]string{
		"SPAMHAUS_API_KEY":   "spamhaus-secret",
		"VIRUSTOTAL_API_KEY": "virustotal-secret",
	}); err != nil {
		t.Fatalf("WriteSecretFile failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected 0600 permissions, got %o", got)
	}
}
