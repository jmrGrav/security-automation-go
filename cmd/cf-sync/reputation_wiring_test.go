package main

import (
	"log/slog"
	"testing"

	"github.com/jm/security-automation-go/internal/config"
	sectrust "github.com/jm/security-automation-go/internal/security/trust"
)

// TestNewWAFBundle_ReputationGateDefaultsToShadow guards the wiring this
// commit adds: the reputation gate (internal/security/reputation.Gate) and
// the auto-ban evaluator's reference to it must both be constructed under a
// default config, and the gate's effective mode must be shadow — never
// enforce — unless an operator explicitly sets reputation_policy.mode:
// "enforce" in YAML. Without this test, a wiring regression that leaves the
// gate nil (inert, as discovered before this fix) or that defaults to
// enforce would pass every other test in the suite, since both gate.go and
// service.go are independently unit-tested in isolation from cmd/cf-sync.
func TestNewWAFBundle_ReputationGateDefaultsToShadow(t *testing.T) {
	cfg := config.DefaultConfig()
	trustRegistry := sectrust.DefaultRegistry()
	logger := slog.Default()

	bundle := newWAFBundle(nil, nil, nil, nil, nil, nil, trustRegistry, cfg, nil, nil, logger)

	gate := bundle.reputationGateService()
	if gate == nil {
		t.Fatal("expected newWAFBundle to construct a non-nil reputation gate")
	}
	if gate.Policy.Mode != "shadow" {
		t.Errorf("expected default reputation policy mode to be shadow, got %q", gate.Policy.Mode)
	}
	if bundle.banEvalService() == nil {
		t.Fatal("expected newWAFBundle to construct a non-nil auto-ban evaluator")
	}
}

// TestReputationPolicyFromConfig_NeverDefaultsToEnforce documents the
// safety invariant this wiring depends on: only the exact literal "enforce"
// in YAML ever produces an enforce-mode policy. Every other value present in
// config.DefaultConfig(), an empty struct, or a typo'd mode string must
// resolve to shadow.
func TestReputationPolicyFromConfig_NeverDefaultsToEnforce(t *testing.T) {
	cases := []struct {
		name string
		cfg  *config.Config
	}{
		{"nil config", nil},
		{"default config", config.DefaultConfig()},
		{"zero-value reputation policy", &config.Config{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			policy := reputationPolicyFromConfig(tc.cfg)
			if policy.Mode != "shadow" {
				t.Errorf("expected mode=shadow, got %q", policy.Mode)
			}
		})
	}
}
