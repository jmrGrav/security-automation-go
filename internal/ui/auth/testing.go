package auth

import "testing"

// SetBcryptCostForTesting overrides the bcrypt work factor for the duration of a test.
// Use bcrypt.MinCost (4) to avoid 30s+ delays per bcrypt call under the race detector.
// The original cost is restored via t.Cleanup.
func SetBcryptCostForTesting(t *testing.T, cost int) {
	t.Helper()
	prev := bcryptCost
	bcryptCost = cost
	t.Cleanup(func() { bcryptCost = prev })
}

// OverrideBcryptCost permanently sets the bcrypt work factor for the test process.
// For use in TestMain where no *testing.T is available.
// Call this once at the start of TestMain before m.Run().
func OverrideBcryptCost(cost int) { bcryptCost = cost }
