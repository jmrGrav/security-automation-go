package auth

import (
	"os"
	"path/filepath"
	"testing"
)

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
