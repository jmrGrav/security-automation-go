package auth

import (
	"crypto/rand"
	"fmt"
	"golang.org/x/crypto/bcrypt"
)

const (
	BootstrapPasswordLength = 32
	bcryptCost              = 12
)

// BootstrapState holds the bootstrap password state: whether bootstrap is active,
// the plaintext password (only in memory), and the bcrypt hash for verification.
type BootstrapState struct {
	IsBootstrap  bool   `json:"is_bootstrap"`
	Password     string `json:"password"`
	PasswordHash string `json:"password_hash"`
}

// GenerateBootstrapPassword generates a cryptographically secure random password.
// Returns a 32-character alphanumeric password suitable for first-boot setup.
func GenerateBootstrapPassword() string {
	const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*"
	b := make([]byte, BootstrapPasswordLength)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	for i := range b {
		b[i] = charset[int(b[i])%len(charset)]
	}
	return string(b)
}

// HashPassword returns a bcrypt hash of the password.
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcryptCost)
	if err != nil {
		return "", fmt.Errorf("hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword checks if the password matches the hash.
func VerifyPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
