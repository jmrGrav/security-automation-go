package ui

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"

	uiauth "github.com/jm/security-automation-go/internal/ui/auth"
)

func TestMain(m *testing.M) {
	// Use minimum bcrypt cost for all UI package tests.
	// Production code uses cost 12; this avoids 30s+ delays per operation
	// when running under the race detector on constrained machines.
	uiauth.OverrideBcryptCost(bcrypt.MinCost)
	os.Exit(m.Run())
}
