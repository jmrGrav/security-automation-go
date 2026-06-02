package auth

import (
	"strings"
	"testing"
)

func TestGenerateBootstrapPassword(t *testing.T) {
	pwd := GenerateBootstrapPassword()
	if len(pwd) < 32 {
		t.Errorf("password too short: got %d, want >= 32", len(pwd))
	}
	if !isPrintableASCII(pwd) {
		t.Errorf("password contains non-printable characters")
	}

	pwd2 := GenerateBootstrapPassword()
	if pwd == pwd2 {
		t.Errorf("generated passwords should not be identical")
	}
}

func TestHashPassword(t *testing.T) {
	password := "test-password-123"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if len(hash) == 0 {
		t.Errorf("hash is empty")
	}
	if strings.HasPrefix(hash, "$2a$") || strings.HasPrefix(hash, "$2y$") || strings.HasPrefix(hash, "$2b$") {
		// bcrypt hash format — valid
	} else {
		t.Errorf("hash does not appear to be bcrypt format: %s", hash)
	}
}

func TestVerifyPassword(t *testing.T) {
	password := "test-password-123"
	hash, _ := HashPassword(password)

	if !VerifyPassword(hash, password) {
		t.Errorf("VerifyPassword failed for correct password")
	}

	if VerifyPassword(hash, "wrong-password") {
		t.Errorf("VerifyPassword succeeded for wrong password")
	}
}

func isPrintableASCII(s string) bool {
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}
