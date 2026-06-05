package auth

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitializeFromPassword_CreatesFileWithHash(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "admin_password")

	if err := InitializeFromPassword(secretFile, "s3cret!"); err != nil {
		t.Fatalf("InitializeFromPassword: %v", err)
	}

	stat, err := os.Stat(secretFile)
	if err != nil {
		t.Fatalf("secret file not created: %v", err)
	}
	if stat.Mode().Perm() != 0o600 {
		t.Errorf("wrong permissions: %o", stat.Mode().Perm())
	}

	state, err := GetBootstrapState(secretFile)
	if err != nil {
		t.Fatalf("GetBootstrapState: %v", err)
	}
	if !state.IsBootstrap {
		t.Error("IsBootstrap should be true")
	}
	if !VerifyPassword(state.PasswordHash, "s3cret!") {
		t.Error("stored hash does not verify with supplied password")
	}
}

func TestInitializeFromPassword_NoOpWhenFileExists(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "admin_password")

	// Create file first
	if err := InitializeFromPassword(secretFile, "first"); err != nil {
		t.Fatalf("first call: %v", err)
	}
	// Second call with different password must be a no-op
	if err := InitializeFromPassword(secretFile, "second"); err != nil {
		t.Fatalf("second call: %v", err)
	}

	state, _ := GetBootstrapState(secretFile)
	if VerifyPassword(state.PasswordHash, "second") {
		t.Error("file was overwritten on second call")
	}
}

func TestInitializeFromPassword_EmptyPasswordNoFile(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "admin_password")

	if err := InitializeFromPassword(secretFile, ""); err == nil {
		t.Error("expected error when password is empty and file does not exist")
	}
}

func TestInitializeBootstrapPassword(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "admin_password")

	// First call — should create password
	pwd1, err := InitializeBootstrapPassword(secretFile)
	if err != nil {
		t.Fatalf("InitializeBootstrapPassword failed: %v", err)
	}
	if len(pwd1) < 32 {
		t.Errorf("password too short: %d", len(pwd1))
	}

	// Verify file was created with correct permissions
	stat, err := os.Stat(secretFile)
	if err != nil {
		t.Fatalf("secret file not created: %v", err)
	}
	perms := stat.Mode().Perm()
	if perms != 0o600 {
		t.Errorf("wrong permissions: got %o, want 0600", perms)
	}

	// Second call — should return same password (not regenerate)
	pwd2, err := InitializeBootstrapPassword(secretFile)
	if err != nil {
		t.Fatalf("second InitializeBootstrapPassword failed: %v", err)
	}
	if pwd1 != pwd2 {
		t.Errorf("password was regenerated on second call")
	}
}

func TestBootstrapState(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "admin_password")

	pwd, _ := InitializeBootstrapPassword(secretFile)
	state, err := GetBootstrapState(secretFile)
	if err != nil {
		t.Fatalf("GetBootstrapState failed: %v", err)
	}
	if state.IsBootstrap != true {
		t.Errorf("IsBootstrap should be true initially")
	}
	if state.PasswordHash == "" {
		t.Errorf("PasswordHash is empty")
	}

	// Verify password works with stored hash
	if !VerifyPassword(state.PasswordHash, pwd) {
		t.Errorf("stored hash does not verify with original password")
	}
}

func TestClearBootstrapState(t *testing.T) {
	tmpDir := t.TempDir()
	secretFile := filepath.Join(tmpDir, "admin_password")

	InitializeBootstrapPassword(secretFile)
	err := ClearBootstrapState(secretFile)
	if err != nil {
		t.Fatalf("ClearBootstrapState failed: %v", err)
	}

	state, err := GetBootstrapState(secretFile)
	if err != nil {
		t.Fatalf("GetBootstrapState after clear failed: %v", err)
	}
	if state.IsBootstrap != false {
		t.Errorf("IsBootstrap should be false after clear")
	}
}
