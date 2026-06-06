package auth

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateInitialPassword_WritesFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initial-admin-password")
	pwd, err := GenerateInitialPassword(path)
	if err != nil {
		t.Fatalf("GenerateInitialPassword: %v", err)
	}
	if len(pwd) < 24 {
		t.Errorf("password too short: %d chars", len(pwd))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimSpace(string(data)) != pwd {
		t.Error("file content does not match returned password")
	}
}

func TestGenerateInitialPassword_Mode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initial-admin-password")
	_, err := GenerateInitialPassword(path)
	if err != nil {
		t.Fatalf("GenerateInitialPassword: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("want 0600, got %04o", info.Mode().Perm())
	}
}

func TestGenerateInitialPassword_IdempotentIfFileExists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initial-admin-password")
	pwd1, _ := GenerateInitialPassword(path)
	pwd2, err := GenerateInitialPassword(path)
	if err != nil {
		t.Fatalf("second call: %v", err)
	}
	if pwd1 != pwd2 {
		t.Error("second call must return same password as first")
	}
}

func TestInvalidateInitialPassword_ZerosFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initial-admin-password")
	_, _ = GenerateInitialPassword(path)
	if err := InvalidateInitialPassword(path); err != nil {
		t.Fatalf("InvalidateInitialPassword: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if strings.TrimSpace(string(data)) != "" {
		t.Errorf("file should be empty after invalidation, got: %q", data)
	}
}

func TestInvalidateInitialPassword_MissingFileIsNoop(t *testing.T) {
	path := filepath.Join(t.TempDir(), "does-not-exist")
	if err := InvalidateInitialPassword(path); err != nil {
		t.Errorf("expected no error for missing file, got: %v", err)
	}
}

func TestVerifyInitialPassword_MatchAndMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initial-admin-password")
	pwd, _ := GenerateInitialPassword(path)

	if !VerifyInitialPassword(path, pwd) {
		t.Error("correct password should verify")
	}
	if VerifyInitialPassword(path, "wrong") {
		t.Error("wrong password should not verify")
	}
}

func TestVerifyInitialPassword_InvalidatedReturnsFalse(t *testing.T) {
	path := filepath.Join(t.TempDir(), "initial-admin-password")
	pwd, _ := GenerateInitialPassword(path)
	_ = InvalidateInitialPassword(path)
	if VerifyInitialPassword(path, pwd) {
		t.Error("invalidated password should not verify")
	}
}
