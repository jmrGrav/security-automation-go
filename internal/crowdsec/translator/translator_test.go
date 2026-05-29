package translator

import (
	"testing"

	"github.com/jm/security-automation-go/internal/crowdsec/models"
	"github.com/jm/security-automation-go/internal/reconciliation"
	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestTranslator_Translate_IPAccessRule(t *testing.T) {
	trans := New()

	plan := &reconciliation.Plan{
		Operations: []reconciliation.Operation{
			{
				OperationID:  "op-1",
				Type:         reconciliation.OpCreate,
				TargetID:     "ip:ip:1.1.1.1:block",
				ResourceType: string(snapshot.ResourceIPAccessRules),
				Payload: map[string]any{
					"configuration": map[string]any{
						"target": "ip",
						"value":  "1.1.1.1",
					},
					"mode": "block",
				},
			},
		},
	}

	actions, err := trans.Translate(plan, snapshot.ProvenanceMetadata{GeneratedBy: "test"})
	if err != nil {
		t.Fatalf("Translation failed: %v", err)
	}

	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}

	a := actions[0]
	if a.Type != models.ActionAddDecision {
		t.Errorf("unexpected action type: %s", a.Type)
	}
	if a.Value != "1.1.1.1" || a.Scope != "ip" {
		t.Errorf("unexpected target details: %s (%s)", a.Value, a.Scope)
	}
}

func TestTranslator_Ordering(t *testing.T) {
	trans := New()

	plan := &reconciliation.Plan{
		Operations: []reconciliation.Operation{
			{OperationID: "o1", Type: reconciliation.OpCreate, TargetID: "z", ResourceType: string(snapshot.ResourceIPAccessRules), Payload: map[string]any{"configuration": map[string]any{}}},
			{OperationID: "o2", Type: reconciliation.OpCreate, TargetID: "a", ResourceType: string(snapshot.ResourceIPAccessRules), Payload: map[string]any{"configuration": map[string]any{}}},
		},
	}

	actions, _ := trans.Translate(plan, snapshot.ProvenanceMetadata{})

	if actions[0].StableIdentityKey != "a" || actions[1].StableIdentityKey != "z" {
		t.Errorf("actions not sorted deterministically: %s, %s", actions[0].StableIdentityKey, actions[1].StableIdentityKey)
	}
}
