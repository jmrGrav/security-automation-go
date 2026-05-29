package validation

import (
	"github.com/jm/security-automation-go/internal/apperr"
	"github.com/jm/security-automation-go/internal/crowdsec/models"
)

// Validator ensures that executable operations are structurally sound and safe.
type Validator struct{}

func New() *Validator {
	return &Validator{}
}

// Validate checks a list of operations for common issues.
func (v *Validator) Validate(actions []models.ExecutableOperation) error {
	const op = "crowdsec.validation.Validate"

	seenSIKs := make(map[string]bool)
	for _, a := range actions {
		if err := v.ValidateSingle(a); err != nil {
			return apperr.Wrapf(op, err, "validation failed for execution %s", a.ExecutionID)
		}

		// Detect potential conflicts or duplicate intents in the same batch
		key := string(a.Type) + ":" + a.StableIdentityKey
		if seenSIKs[key] {
			return apperr.Newf(op, "duplicate action detected in batch: %s", key)
		}
		seenSIKs[key] = true
	}

	return nil
}

// ValidateSingle checks one operation.
func (v *Validator) ValidateSingle(a models.ExecutableOperation) error {
	const op = "crowdsec.validation.ValidateSingle"

	if a.ExecutionID == "" {
		return apperr.New(op, "missing ExecutionID")
	}
	if a.Type == "" {
		return apperr.New(op, "missing ActionType")
	}
	if a.StableIdentityKey == "" {
		return apperr.New(op, "missing StableIdentityKey")
	}
	if a.Value == "" {
		return apperr.New(op, "missing target Value (IP/CIDR)")
	}

	if a.Type == models.ActionAddDecision {
		if a.Scope == "" {
			return apperr.New(op, "missing Scope for addition")
		}
	}

	return nil
}
