package auth

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// GenerateInitialPassword writes a one-time setup password in plaintext to path
// (mode 0600). If path already exists and is non-empty, reads and returns the
// existing password — this call is idempotent. Never log the returned value.
func GenerateInitialPassword(path string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", fmt.Errorf("create runtime dir: %w", err)
	}

	// If file exists and is non-empty, return existing password.
	if data, err := os.ReadFile(path); err == nil {
		if existing := strings.TrimSpace(string(data)); existing != "" {
			return existing, nil
		}
	}

	pwd := GenerateBootstrapPassword() // 32-char secure random from password.go

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(pwd), 0o600); err != nil {
		return "", fmt.Errorf("write initial password: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return "", fmt.Errorf("install initial password: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", fmt.Errorf("chmod initial password: %w", err)
	}

	return pwd, nil
}

// InvalidateInitialPassword truncates the password file so it can no longer be used.
// It is a no-op if the file does not exist.
func InvalidateInitialPassword(path string) error {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return os.WriteFile(path, []byte(""), 0o600)
}

// VerifyInitialPassword returns true iff the file exists, is non-empty, and its
// trimmed content matches candidate. Never log candidate.
func VerifyInitialPassword(path, candidate string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	stored := strings.TrimSpace(string(data))
	return stored != "" && stored == candidate
}
