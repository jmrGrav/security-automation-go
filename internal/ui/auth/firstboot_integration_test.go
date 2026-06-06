package auth_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jm/security-automation-go/internal/ui/auth"
)

// TestFirstBootEndToEnd proves the SECURITY_AUTOMATION_INITIAL_ADMIN_PASSWORD
// bootstrap path:
//  1. Empty env, fresh credential file
//  2. Password supplied via env var → bcrypt hash written
//  3. No plaintext stored in the file
//  4. VerifyPassword succeeds
//  5. "Restart": calling InitializeFromPassword again is a no-op
//  6. Original credential preserved
func TestFirstBootEndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	credFile := filepath.Join(tmpDir, "admin_password")
	const bootstrapPassword = "BootstrapPass1!Secure"

	// --- Boot 1: fresh credential file ---
	if err := auth.InitializeFromPassword(credFile, bootstrapPassword); err != nil {
		t.Fatalf("InitializeFromPassword (boot 1): %v", err)
	}

	// Verify the file exists and has restricted permissions.
	info, err := os.Stat(credFile)
	if err != nil {
		t.Fatalf("credential file not created: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("expected file permissions 0600, got %04o", info.Mode().Perm())
	}

	// Verify no plaintext is stored.
	raw, err := os.ReadFile(credFile)
	if err != nil {
		t.Fatalf("read credential file: %v", err)
	}
	if strings.Contains(string(raw), bootstrapPassword) {
		t.Error("plaintext password found in credential file — MUST NOT store plaintext")
	}

	// Verify the stored value is a bcrypt hash (bcrypt hashes start with "$2").
	var state auth.BootstrapState
	if err := json.Unmarshal(raw, &state); err != nil {
		t.Fatalf("unmarshal credential file: %v", err)
	}
	if !strings.HasPrefix(state.PasswordHash, "$2") {
		t.Errorf("stored hash does not look like a bcrypt hash: %q", state.PasswordHash)
	}
	if !state.IsBootstrap {
		t.Error("IsBootstrap must be true after first boot")
	}

	// Verify the bootstrap password verifies successfully.
	if !auth.VerifyPassword(state.PasswordHash, bootstrapPassword) {
		t.Error("VerifyPassword failed for bootstrap password")
	}

	// --- Boot 2: restart with a DIFFERENT env password --- must be no-op ---
	const differentPassword = "DifferentPass2!XYZ"
	if err := auth.InitializeFromPassword(credFile, differentPassword); err != nil {
		t.Fatalf("InitializeFromPassword (boot 2): %v", err)
	}

	// Credential file must not have changed.
	raw2, err := os.ReadFile(credFile)
	if err != nil {
		t.Fatalf("read credential file after boot 2: %v", err)
	}
	if string(raw2) != string(raw) {
		t.Error("credential file was overwritten on second boot — InitializeFromPassword must be idempotent")
	}

	// Original password still works.
	var state2 auth.BootstrapState
	if err := json.Unmarshal(raw2, &state2); err != nil {
		t.Fatalf("unmarshal after boot 2: %v", err)
	}
	if !auth.VerifyPassword(state2.PasswordHash, bootstrapPassword) {
		t.Error("original bootstrap password no longer verifies after restart — credential corrupted")
	}
	if auth.VerifyPassword(state2.PasswordHash, differentPassword) {
		t.Error("restart password accepted — IdempotencyInvariant violated")
	}
}
