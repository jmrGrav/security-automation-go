package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

// TestVerifyRecoveryKey_RoundTrip tests the generate → encode → hash → verify path.
func TestVerifyRecoveryKey_RoundTrip(t *testing.T) {
	raw := make([]byte, adminRecoveryKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(raw)
	storedHash := hex.EncodeToString(sha256sum(raw))

	ok, err := verifyRecoveryKey(encoded, storedHash)
	if err != nil {
		t.Fatalf("verifyRecoveryKey returned error: %v", err)
	}
	if !ok {
		t.Error("expected valid key to verify successfully")
	}
}

// TestVerifyRecoveryKey_WrongKey ensures a different key is rejected.
func TestVerifyRecoveryKey_WrongKey(t *testing.T) {
	raw := make([]byte, adminRecoveryKeyBytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	storedHash := hex.EncodeToString(sha256sum(raw))

	// A different key — same length but different bytes.
	other := make([]byte, adminRecoveryKeyBytes)
	if _, err := rand.Read(other); err != nil {
		t.Fatalf("rand.Read other: %v", err)
	}
	wrongEncoded := base64.RawURLEncoding.EncodeToString(other)

	ok, err := verifyRecoveryKey(wrongEncoded, storedHash)
	if err != nil {
		t.Fatalf("unexpected error for wrong key: %v", err)
	}
	if ok {
		t.Error("expected wrong key to be rejected")
	}
}

// TestVerifyRecoveryKey_RotateInvalidatesOld ensures rotating the stored hash
// invalidates the old key while the new key verifies.
func TestVerifyRecoveryKey_RotateInvalidatesOld(t *testing.T) {
	db, err := sqlite.New(t.TempDir())
	if err != nil {
		t.Fatalf("sqlite.New: %v", err)
	}
	defer db.Close()
	store := sqlite.NewSetupStore(db)
	ctx := context.Background()

	// First key
	oldRaw := make([]byte, adminRecoveryKeyBytes)
	if _, err := rand.Read(oldRaw); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	oldEncoded := base64.RawURLEncoding.EncodeToString(oldRaw)
	oldHash := hex.EncodeToString(sha256sum(oldRaw))
	if err := store.SetRecoveryKeyHash(ctx, oldHash); err != nil {
		t.Fatalf("SetRecoveryKeyHash: %v", err)
	}

	// Rotate: second key replaces it.
	newRaw := make([]byte, adminRecoveryKeyBytes)
	if _, err := rand.Read(newRaw); err != nil {
		t.Fatalf("rand.Read new: %v", err)
	}
	newEncoded := base64.RawURLEncoding.EncodeToString(newRaw)
	newHash := hex.EncodeToString(sha256sum(newRaw))
	if err := store.SetRecoveryKeyHash(ctx, newHash); err != nil {
		t.Fatalf("SetRecoveryKeyHash (rotate): %v", err)
	}

	// Verify stored hash is now the new one.
	storedHex, ok, err := store.GetRecoveryKeyHash(ctx)
	if err != nil || !ok {
		t.Fatalf("GetRecoveryKeyHash: err=%v ok=%v", err, ok)
	}

	// Old key must be rejected.
	rejected, err := verifyRecoveryKey(oldEncoded, storedHex)
	if err != nil {
		t.Fatalf("verifyRecoveryKey old key: %v", err)
	}
	if rejected {
		t.Error("old key should be rejected after rotation")
	}

	// New key must be accepted.
	accepted, err := verifyRecoveryKey(newEncoded, storedHex)
	if err != nil {
		t.Fatalf("verifyRecoveryKey new key: %v", err)
	}
	if !accepted {
		t.Error("new key should be accepted after rotation")
	}
}
