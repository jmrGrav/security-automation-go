package cloudflare_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/fixtures"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/snapshot"
)

func TestDiscovery_IPAccessRules_Normalization_Replay(t *testing.T) {
	// 1. Setup fixtures
	f1 := fixtures.SanitizedFixture{
		SourceFixtureID: "rules-page1",
		ResponseStatus:  200,
		ResponseBody: []byte(`{
			"result": [
				{"id": "rule1", "mode": "block", "notes": "test", "configuration": {"target": "ip", "value": "1.1.1.1"}}
			],
			"success": true,
			"result_info": {"page": 1, "per_page": 1, "count": 1, "total_count": 1, "total_pages": 1}
		}`),
	}
	f1.IntegrityHash = fixtures.IntegrityHashSanitized(f1)

	meta := fixtures.ReplayMetadata{
		Ordering: []string{"rules-page1"},
	}

	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{f1}, meta)
	doer := fixtures.NewReplayDoer(engine)

	// 2. Setup Client
	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(doer))
	cf := client.New("fake-token", hc)

	// 3. Execute Discovery (Returns Provider Models)
	ctx := context.Background()
	rules, err := cf.Discovery.ListIPAccessRules(ctx, "zone-id")
	if err != nil {
		t.Fatalf("Discovery failed: %v", err)
	}

	// 4. Normalize (Returns Snapshot Objects)
	normalized := cf.Normalizer.IPAccessRules(rules)

	// 5. Build Snapshot
	builder := snapshot.NewBuilder()
	snap, err := builder.Build(snapshot.BuilderInput{
		Source: snapshot.SnapshotSource{
			Provider: "cloudflare",
			Endpoint: "ip_access_rules",
		},
		ResourceType: snapshot.ResourceIPAccessRules,
		Scope: snapshot.RawScope{
			ZoneID: "zone-id",
		},
		RawJSON:     f1.ResponseBody,
		ObjectsPath: []string{"result"},
	})
	if err != nil {
		t.Fatalf("Snapshot build failed: %v", err)
	}

	// 6. Validate results
	if snap.Collection.ObjectCount != 1 {
		t.Errorf("expected 1 object, got %d", snap.Collection.ObjectCount)
	}
	if snap.Collection.Objects[0].StableIdentityKey != "ip:ip:1.1.1.1:block" {
		t.Errorf("unexpected SIK: %s", snap.Collection.Objects[0].StableIdentityKey)
	}

	// Check that the normalizer output matches the builder output for the same item
	if normalized[0].StableIdentityKey != snap.Collection.Objects[0].StableIdentityKey {
		t.Errorf("normalizer/builder SIK mismatch: %s != %s", normalized[0].StableIdentityKey, snap.Collection.Objects[0].StableIdentityKey)
	}
}

func TestDiscovery_429_Retry(t *testing.T) {
	// Setup a fixture that fails with 429 once then succeeds
	fErr := fixtures.SanitizedFixture{
		SourceFixtureID: "fail",
		ResponseStatus:  http.StatusTooManyRequests,
		ResponseHeaders: map[string]string{"Retry-After": "1"},
		ResponseBody:    []byte(`{"success":false,"errors":[{"code":1001,"message":"Rate limit"}]}`),
	}
	fOk := fixtures.SanitizedFixture{
		SourceFixtureID: "success",
		ResponseStatus:  200,
		ResponseBody:    []byte(`{"result":[],"success":true,"result_info":{"total_pages":1}}`),
	}

	fErr.IntegrityHash = fixtures.IntegrityHashSanitized(fErr)
	fOk.IntegrityHash = fixtures.IntegrityHashSanitized(fOk)

	meta := fixtures.ReplayMetadata{
		Ordering: []string{"fail", "success"},
	}

	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{fErr, fOk}, meta)
	doer := fixtures.NewReplayDoer(engine)

	hc := httpclient.New(config.HTTPConfig{RetryMax: 3}, httpclient.WithDoer(doer))
	cf := client.New("fake-token", hc)

	ctx := context.Background()
	_, err := cf.Discovery.ListZones(ctx)
	if err != nil {
		t.Fatalf("Expected success after retry, got %v", err)
	}
}
