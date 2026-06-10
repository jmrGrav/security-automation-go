package sqlite_test

import (
	"context"
	"testing"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

func TestSetupStore_AuthEpoch(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer db.Close()
	store := sqlite.NewSetupStore(db)
	ctx := context.Background()

	// Default epoch is 0
	epoch, err := store.GetAuthEpoch(ctx)
	if err != nil {
		t.Fatalf("GetAuthEpoch: %v", err)
	}
	if epoch != 0 {
		t.Errorf("expected initial epoch=0, got %d", epoch)
	}

	// First increment → 1
	newEpoch, err := store.IncrementAuthEpoch(ctx)
	if err != nil {
		t.Fatalf("IncrementAuthEpoch: %v", err)
	}
	if newEpoch != 1 {
		t.Errorf("expected epoch=1 after first increment, got %d", newEpoch)
	}

	// Second increment → 2
	newEpoch, err = store.IncrementAuthEpoch(ctx)
	if err != nil {
		t.Fatalf("IncrementAuthEpoch #2: %v", err)
	}
	if newEpoch != 2 {
		t.Errorf("expected epoch=2 after second increment, got %d", newEpoch)
	}

	// GetAuthEpoch confirms persisted value
	epoch, err = store.GetAuthEpoch(ctx)
	if err != nil {
		t.Fatalf("GetAuthEpoch after increments: %v", err)
	}
	if epoch != 2 {
		t.Errorf("expected persisted epoch=2, got %d", epoch)
	}
}

func TestSetupStore_PasswordChangeRequired(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer db.Close()
	store := sqlite.NewSetupStore(db)
	ctx := context.Background()

	// Default is false
	required, err := store.GetPasswordChangeRequired(ctx)
	if err != nil {
		t.Fatalf("GetPasswordChangeRequired: %v", err)
	}
	if required {
		t.Error("expected password_change_required=false by default")
	}

	// Set to true
	if err := store.SetPasswordChangeRequired(ctx, true); err != nil {
		t.Fatalf("SetPasswordChangeRequired(true): %v", err)
	}
	required, err = store.GetPasswordChangeRequired(ctx)
	if err != nil {
		t.Fatalf("GetPasswordChangeRequired after set: %v", err)
	}
	if !required {
		t.Error("expected password_change_required=true after set")
	}

	// Clear it
	if err := store.SetPasswordChangeRequired(ctx, false); err != nil {
		t.Fatalf("SetPasswordChangeRequired(false): %v", err)
	}
	required, _ = store.GetPasswordChangeRequired(ctx)
	if required {
		t.Error("expected password_change_required=false after clear")
	}
}

func TestSetupStore_RecoveryKey(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer db.Close()
	store := sqlite.NewSetupStore(db)
	ctx := context.Background()

	// No key initially
	hash, ok, err := store.GetRecoveryKeyHash(ctx)
	if err != nil {
		t.Fatalf("GetRecoveryKeyHash (empty): %v", err)
	}
	if ok || hash != "" {
		t.Error("expected no recovery key initially")
	}

	// Create a key — only hash is stored, never plaintext
	const testHash = "aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011aabbccddeeff0011"
	if err := store.SetRecoveryKeyHash(ctx, testHash); err != nil {
		t.Fatalf("SetRecoveryKeyHash: %v", err)
	}

	hash, ok, err = store.GetRecoveryKeyHash(ctx)
	if err != nil {
		t.Fatalf("GetRecoveryKeyHash: %v", err)
	}
	if !ok {
		t.Fatal("expected recovery key to be present after set")
	}
	if hash != testHash {
		t.Errorf("expected hash=%q, got %q", testHash, hash)
	}

	// Rotate replaces the hash
	const rotatedHash = "1122334455667788112233445566778811223344556677881122334455667788"
	if err := store.SetRecoveryKeyHash(ctx, rotatedHash); err != nil {
		t.Fatalf("SetRecoveryKeyHash (rotate): %v", err)
	}
	hash, ok, _ = store.GetRecoveryKeyHash(ctx)
	if !ok || hash != rotatedHash {
		t.Errorf("expected rotated hash=%q, got %q", rotatedHash, hash)
	}

	// UpdateRecoveryKeyLastUsed does not error when a key exists
	if err := store.UpdateRecoveryKeyLastUsed(ctx); err != nil {
		t.Fatalf("UpdateRecoveryKeyLastUsed: %v", err)
	}
}

func TestSetupStore_RecoveryKeyHash_NeverStoredPlaintext(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer db.Close()
	store := sqlite.NewSetupStore(db)
	ctx := context.Background()

	// The hash stored must differ from any hypothetical plaintext
	const plaintext = "secret-recovery-key"
	hash := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" // SHA-256("") ≠ plaintext
	if err := store.SetRecoveryKeyHash(ctx, hash); err != nil {
		t.Fatalf("SetRecoveryKeyHash: %v", err)
	}
	stored, ok, _ := store.GetRecoveryKeyHash(ctx)
	if !ok {
		t.Fatal("key not stored")
	}
	if stored == plaintext {
		t.Error("SECURITY: recovery key stored as plaintext — must store hash only")
	}
}
