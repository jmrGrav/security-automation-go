package validation_test

import (
	"testing"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/crowdsec/validation"
)

func validOp() models.ExecutableOperation {
	return models.ExecutableOperation{
		ExecutionID:       "exec-1",
		Type:              models.ActionAddDecision,
		StableIdentityKey: "crowdsec:ip:1.2.3.4",
		Scope:             "ip",
		Value:             "1.2.3.4",
		Duration:          "4h",
		Reason:            "test",
	}
}

func TestValidateSingle_Valid(t *testing.T) {
	v := validation.New()
	if err := v.ValidateSingle(validOp()); err != nil {
		t.Errorf("valid operation rejected: %v", err)
	}
}

func TestValidateSingle_MissingFields(t *testing.T) {
	v := validation.New()

	cases := []struct {
		name string
		op   models.ExecutableOperation
	}{
		{
			"missing ExecutionID",
			func() models.ExecutableOperation { o := validOp(); o.ExecutionID = ""; return o }(),
		},
		{
			"missing ActionType",
			func() models.ExecutableOperation { o := validOp(); o.Type = ""; return o }(),
		},
		{
			"missing StableIdentityKey",
			func() models.ExecutableOperation { o := validOp(); o.StableIdentityKey = ""; return o }(),
		},
		{
			"missing Value",
			func() models.ExecutableOperation { o := validOp(); o.Value = ""; return o }(),
		},
		{
			"add decision missing Scope",
			func() models.ExecutableOperation {
				o := validOp()
				o.Type = models.ActionAddDecision
				o.Scope = ""
				return o
			}(),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := v.ValidateSingle(tc.op); err == nil {
				t.Errorf("expected error for %q, got nil", tc.name)
			}
		})
	}
}

// TestValidateSingle_DeleteDoesNotRequireScope verifies delete operations
// succeed without a Scope field (only add requires it).
func TestValidateSingle_DeleteDoesNotRequireScope(t *testing.T) {
	v := validation.New()
	op := validOp()
	op.Type = models.ActionDeleteDecision
	op.Scope = "" // no scope needed for delete
	if err := v.ValidateSingle(op); err != nil {
		t.Errorf("delete without scope should be valid: %v", err)
	}
}

func TestValidate_EmptyBatch(t *testing.T) {
	v := validation.New()
	if err := v.Validate(nil); err != nil {
		t.Errorf("empty batch should be valid: %v", err)
	}
}

func TestValidate_DuplicateSIK_SameType(t *testing.T) {
	v := validation.New()
	op := validOp()
	batch := []models.ExecutableOperation{op, op} // same SIK + type twice
	if err := v.Validate(batch); err == nil {
		t.Error("duplicate SIK in same batch must be rejected")
	}
}

func TestValidate_SameSIK_DifferentType_NotDuplicate(t *testing.T) {
	v := validation.New()
	add := validOp()
	add.Type = models.ActionAddDecision
	add.ExecutionID = "exec-add"

	del := validOp()
	del.Type = models.ActionDeleteDecision
	del.ExecutionID = "exec-del"
	del.Scope = "" // delete doesn't require scope

	// Different types → different SIK key (type:sik) → allowed
	if err := v.Validate([]models.ExecutableOperation{add, del}); err != nil {
		t.Errorf("different type with same SIK value should be allowed: %v", err)
	}
}

func TestValidate_PropagatesValidateSingleErrors(t *testing.T) {
	v := validation.New()
	bad := validOp()
	bad.ExecutionID = "" // invalid
	if err := v.Validate([]models.ExecutableOperation{bad}); err == nil {
		t.Error("validate must surface single-op validation errors")
	}
}

// TestValidate_TableDriven covers multiple batch scenarios.
func TestValidate_TableDriven(t *testing.T) {
	v := validation.New()

	cases := []struct {
		name    string
		ops     []models.ExecutableOperation
		wantErr bool
	}{
		{"single valid op", []models.ExecutableOperation{validOp()}, false},
		{"two different ops", []models.ExecutableOperation{
			func() models.ExecutableOperation {
				o := validOp()
				o.ExecutionID = "e1"
				o.StableIdentityKey = "sik1"
				return o
			}(),
			func() models.ExecutableOperation {
				o := validOp()
				o.ExecutionID = "e2"
				o.StableIdentityKey = "sik2"
				return o
			}(),
		}, false},
		{"duplicate SIK same type", []models.ExecutableOperation{validOp(), validOp()}, true},
		{"invalid op in batch", []models.ExecutableOperation{
			func() models.ExecutableOperation { o := validOp(); o.Value = ""; return o }(),
		}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.Validate(tc.ops)
			if (err != nil) != tc.wantErr {
				t.Errorf("wantErr=%v, got err=%v", tc.wantErr, err)
			}
		})
	}
}
