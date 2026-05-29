package mutate_test

import (
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/mutate"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/fixtures"
	"github.com/jm/security-automation-go/internal/httpclient"
)

func TestIPAccessRuleMutator_Execute_Create_Replay(t *testing.T) {
	// 1. Setup fixtures
	f1 := fixtures.SanitizedFixture{
		SourceFixtureID: "rule-create",
		ResponseStatus:  200,
		ResponseBody:    []byte(`{"result": {"id": "cf-rule-123"}, "success": true}`),
	}
	f1.IntegrityHash = fixtures.IntegrityHashSanitized(f1)

	meta := fixtures.ReplayMetadata{
		Ordering: []string{"rule-create"},
	}

	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{f1}, meta)
	doer := fixtures.NewReplayDoer(engine)

	// 2. Setup Mutator
	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(doer))
	trans := transport.New(hc, "fake-token")
	m := mutate.NewIPAccessRuleMutator(trans, "zone-id")

	// 3. Execute
	op := execution.MutationOperation{
		Type:              "create",
		StableIdentityKey: "ip:ip:1.1.1.1:block",
		Payload: map[string]any{
			"mode": "block",
			"configuration": map[string]any{
				"target": "ip",
				"value":  "1.1.1.1",
			},
		},
	}

	resID, err := m.Execute(op)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if resID != "cf-rule-123" {
		t.Errorf("expected result ID cf-rule-123, got %s", resID)
	}
}

func TestIPAccessRuleMutator_Execute_Delete_Replay(t *testing.T) {
	// 1. Setup fixtures
	f1 := fixtures.SanitizedFixture{
		SourceFixtureID: "rule-delete",
		ResponseStatus:  200,
		ResponseBody:    []byte(`{"result": {"id": "cf-rule-123"}, "success": true}`),
	}
	f1.IntegrityHash = fixtures.IntegrityHashSanitized(f1)

	meta := fixtures.ReplayMetadata{
		Ordering: []string{"rule-delete"},
	}

	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{f1}, meta)
	doer := fixtures.NewReplayDoer(engine)

	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(doer))
	trans := transport.New(hc, "fake-token")
	m := mutate.NewIPAccessRuleMutator(trans, "zone-id")

	// 3. Execute
	op := execution.MutationOperation{
		Type:             "delete",
		ProviderObjectID: "cf-rule-123",
	}

	_, err := m.Execute(op)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
}
