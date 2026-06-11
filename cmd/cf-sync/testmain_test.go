package main

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	uiauth "github.com/jm/security-automation-go/internal/ui/auth"
)

// TestMain sets bcrypt to minimum cost before running any tests in this package.
// Without this, wizard integration tests that call HashPassword + VerifyPassword
// under the -race detector with full-suite CPU contention take 30+ seconds per
// bcrypt call, causing the 20–30 s HTTP client timeouts to fire intermittently.
func TestMain(m *testing.M) {
	uiauth.OverrideBcryptCost(bcrypt.MinCost)
	os.Exit(m.Run())
}
