package opa_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/policy/opa"
)

// TestBundleLoader_LoadDefault_Success verifies the loader reads a Rego file
// from the configured directory.
func TestBundleLoader_LoadDefault_Success(t *testing.T) {
	dir := t.TempDir()
	regoContent := `package cfsync.admission
default decision = "allow"
`
	if err := os.WriteFile(filepath.Join(dir, "admission.rego"), []byte(regoContent), 0644); err != nil {
		t.Fatal(err)
	}

	loader := opa.NewBundleLoader(dir)
	code, err := loader.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault failed: %v", err)
	}
	if code == "" {
		t.Error("LoadDefault must return non-empty Rego code")
	}
}

// TestBundleLoader_LoadDefault_FileNotFound verifies an error is returned when
// the admission.rego file doesn't exist — the caller should handle gracefully.
func TestBundleLoader_LoadDefault_FileNotFound(t *testing.T) {
	loader := opa.NewBundleLoader("/nonexistent/path/that/does/not/exist")
	_, err := loader.LoadDefault()
	if err == nil {
		t.Error("missing file must return error")
	}
}

// TestBundleLoader_LoadDefault_EmptyDir verifies the error case when the dir
// exists but contains no admission.rego.
func TestBundleLoader_LoadDefault_EmptyDir(t *testing.T) {
	dir := t.TempDir()
	loader := opa.NewBundleLoader(dir)
	_, err := loader.LoadDefault()
	if err == nil {
		t.Error("empty dir must return error (no admission.rego)")
	}
}

// TestBundleLoader_LoadAndEval verifies end-to-end: load from file then
// evaluate through the engine to confirm the policy works correctly.
func TestBundleLoader_LoadAndEval(t *testing.T) {
	dir := t.TempDir()
	regoContent := `package cfsync.admission
default decision = "allow"
decision = "deny" {
    input.runtime.breaker_state == "open"
}
`
	if err := os.WriteFile(filepath.Join(dir, "admission.rego"), []byte(regoContent), 0644); err != nil {
		t.Fatal(err)
	}

	loader := opa.NewBundleLoader(dir)
	code, err := loader.LoadDefault()
	if err != nil {
		t.Fatalf("LoadDefault: %v", err)
	}

	eng, err := opa.NewEngine(context.Background(), discardLogger, code)
	if err != nil {
		t.Fatalf("NewEngine from loaded code: %v", err)
	}

	dec, _, err := eng.Evaluate(context.Background(), models.PolicyInput{
		Runtime: models.RuntimeContext{BreakerState: "open"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if dec != models.DecisionDeny {
		t.Errorf("want Deny from loaded policy, got %q", dec)
	}
}
