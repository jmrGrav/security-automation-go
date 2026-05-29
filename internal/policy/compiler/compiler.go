package compiler

import (
	"fmt"
	"time"

	"github.com/jm/security-automation-go/internal/policy/intent"
)

// Compiler translates business intents into technical constraints.
type Compiler struct{}

func New() *Compiler {
	return &Compiler{}
}

func (c *Compiler) Compile(it intent.Intent) (intent.Constraints, error) {
	switch it.Mode {
	case intent.ModeParanoid:
		return intent.Constraints{
			RollbackAggressiveness: 1.0,
			MutationBudget:         50,
			DestructiveBudget:      10,
			DriftTolerance:         0.01,
			RetryBackoffMultiplier: 1.5,
			QuarantineThreshold:    0.5,
			RequireApproval:        true,
			CooldownDuration:       30 * time.Minute,
		}, nil

	case intent.ModeAvailabilityFirst:
		return intent.Constraints{
			RollbackAggressiveness: 0.2,
			MutationBudget:         500,
			DestructiveBudget:      50,
			DriftTolerance:         0.2,
			RetryBackoffMultiplier: 2.5,
			QuarantineThreshold:    0.9,
			RequireApproval:        false,
			CooldownDuration:       5 * time.Minute,
		}, nil

	case intent.ModeTerraformFriendly:
		return intent.Constraints{
			RollbackAggressiveness: 0.0,
			MutationBudget:         20,
			DestructiveBudget:      0,
			DriftTolerance:         0.5,
			RetryBackoffMultiplier: 5.0,
			QuarantineThreshold:    0.3,
			RequireApproval:        true,
			CooldownDuration:       1 * time.Hour,
		}, nil

	default:
		return intent.Constraints{}, fmt.Errorf("unsupported intent mode: %s", it.Mode)
	}
}
