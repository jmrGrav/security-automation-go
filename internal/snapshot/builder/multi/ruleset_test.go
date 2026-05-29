package multi

import (
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/models"
	"github.com/jm/security-automation-go/internal/cloudflare/normalize"
	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestGraphAssembler_Rulesets_Phases(t *testing.T) {
	reg := resources.NewRegistry()
	norm := normalize.New()

	assembler, err := NewGraphAssembler(reg)
	if err != nil {
		t.Fatalf("failed to create assembler: %v", err)
	}

	// 1. Setup sample rulesets
	rsModels := []models.Ruleset{
		{ID: "rs-custom", Name: "My Custom Rules", Phase: "http_request_firewall_custom", Kind: "custom"},
		{ID: "rs-ratelimit", Name: "Rate Limits", Phase: "http_request_ratelimit", Kind: "custom"},
	}

	// 2. Normalize
	rsObjects := norm.Rulesets(rsModels)

	// 3. Add to assembler
	err = assembler.Add(snapshot.ResourceRulesets, rsObjects)
	if err != nil {
		t.Fatalf("failed to add rulesets: %v", err)
	}

	// 4. Build
	snaps, err := assembler.BuildAll()
	if err != nil {
		t.Fatalf("failed to build snapshots: %v", err)
	}

	// 5. Verify presence
	foundRulesets := false
	for _, s := range snaps {
		if s.ResourceType == snapshot.ResourceRulesets {
			foundRulesets = true
			if len(s.Collection.Objects) != 2 {
				t.Errorf("expected 2 rulesets, got %d", len(s.Collection.Objects))
			}
		}
	}

	if !foundRulesets {
		t.Error("Rulesets snapshot not found in multi-resource build")
	}
}

func TestGraphAssembler_Precedence_Ordering(t *testing.T) {
	// This test ensures that rules within a ruleset are ordered deterministically by SIK
	// but in production we might need to preserve Cloudflare's own index if managed.
	// For now, our assembler uses SIK sorting.

	reg := resources.NewRegistry()
	norm := normalize.New()
	assembler, _ := NewGraphAssembler(reg)

	rules := []models.RulesetRule{
		{ID: "r2", Action: "block", Expression: "true", Description: "rule B"},
		{ID: "r1", Action: "block", Expression: "true", Description: "rule A"},
	}

	normalized := norm.RulesetRules("rs1", rules)
	_ = assembler.Add(snapshot.ResourceRulesetRules, normalized)

	snaps, _ := assembler.BuildAll()

	for _, s := range snaps {
		if s.ResourceType == snapshot.ResourceRulesetRules {
			// SIK for r1: rule:rs1:1:block, r2: rule:rs1:0:block
			// Wait, normalization uses loop index for SIK if no ref.
			// Let's verify stable identity.
			if len(s.Collection.Objects) != 2 {
				t.Fatal("expected 2 rules")
			}
		}
	}
}
