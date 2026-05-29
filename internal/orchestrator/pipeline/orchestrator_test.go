package pipeline_test

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec/translator"
	"github.com/jm/security-automation-go/internal/crowdsec/validation"
	"github.com/jm/security-automation-go/internal/fixtures"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/orchestrator/pipeline"
	"github.com/jm/security-automation-go/internal/policy/admission"
	polengine "github.com/jm/security-automation-go/internal/policy/engine"
	"github.com/jm/security-automation-go/internal/policy/federation"
	polmodels "github.com/jm/security-automation-go/internal/policy/models"
	"github.com/jm/security-automation-go/internal/policy/opa"
	"github.com/jm/security-automation-go/internal/policy/replay/recorder"
	"github.com/jm/security-automation-go/internal/reconciliation"
	rolexecutor "github.com/jm/security-automation-go/internal/rollback/executor"
	rolplanner "github.com/jm/security-automation-go/internal/rollback/planner"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/bus"
	"github.com/jm/security-automation-go/internal/runtime/convergence"
	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/drift"
	driftmemory "github.com/jm/security-automation-go/internal/runtime/drift/memory"
	rtengine "github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/health"
	"github.com/jm/security-automation-go/internal/runtime/invariants"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/snapshot"
)

// ReplayDoer adapts the fixtures.ReplayEngine to the httpclient.Doer interface.
type ReplayDoer struct {
	engine *fixtures.ReplayEngine
}

func (d *ReplayDoer) Do(req *http.Request) (*http.Response, error) {
	res, err := d.engine.Next(req.Context())
	if err != nil {
		if err.Error() == "EOF" {
			return nil, io.EOF
		}
		return nil, err
	}

	if res.Error != nil {
		return nil, res.Error
	}

	resp := &http.Response{
		StatusCode: res.Response.ResponseStatus,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader(res.Response.ResponseBody)),
		Request:    req,
	}

	for k, v := range res.Response.ResponseHeaders {
		resp.Header.Set(k, v)
	}

	return resp, nil
}

func TestOrchestrator_DryRun_EndToEnd(t *testing.T) {
	// 1. Setup fixtures (One page of IP rules)
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
	orch := setupTestOrchestrator(engine)

	// 2. Run Pipeline
	ctx := context.Background()
	prov := snapshot.ProvenanceMetadata{GeneratedBy: "test"}

	res, err := orch.DryRun(ctx, "zone-id", snapshot.ResourceIPAccessRules, prov)
	if err != nil {
		t.Fatalf("DryRun failed: %v", err)
	}

	// 3. Validate end-to-end result
	if !res.Success {
		t.Error("expected result success to be true")
	}
	if res.Snapshot.ObjectCount != 1 {
		t.Errorf("expected 1 object in snapshot, got %d", res.Snapshot.ObjectCount)
	}
}

func TestOrchestrator_DryRun_DuplicateSIK(t *testing.T) {
	// Setup fixture with duplicate items (same identity)
	f1 := fixtures.SanitizedFixture{
		SourceFixtureID: "rules-dup",
		ResponseStatus:  200,
		ResponseBody: []byte(`{
			"result": [
				{"id": "r1", "mode": "block", "configuration": {"target": "ip", "value": "1.1.1.1"}},
				{"id": "r2", "mode": "block", "configuration": {"target": "ip", "value": "1.1.1.1"}}
			],
			"success": true,
			"result_info": {"total_pages": 1}
		}`),
	}
	f1.IntegrityHash = fixtures.IntegrityHashSanitized(f1)

	engine := fixtures.NewReplayEngine([]fixtures.SanitizedFixture{f1}, fixtures.ReplayMetadata{Ordering: []string{"rules-dup"}})
	orch := setupTestOrchestrator(engine)

	_, err := orch.DryRun(context.Background(), "z", snapshot.ResourceIPAccessRules, snapshot.ProvenanceMetadata{})
	if err == nil || !strings.Contains(err.Error(), "duplicate StableIdentityKey") {
		t.Errorf("expected duplicate SIK error, got %v", err)
	}
}

func setupTestOrchestrator(engine *fixtures.ReplayEngine) *pipeline.Orchestrator {
	doer := fixtures.NewReplayDoer(engine)
	hc := httpclient.New(config.HTTPConfig{}, httpclient.WithDoer(doer))
	cf := client.New("fake", hc)

	// Mock runtime components
	tmpDir := "/tmp/test-state-" + strings.ReplaceAll(time.Now().Format(time.RFC3339Nano), ":", "-")
	stateStore := state.NewStateStore(tmpDir)
	jsonlJournal := journal.NewJSONLJournal(tmpDir + "/audit.jsonl")
	cb := breaker.New(5, time.Minute, time.Minute)
	eventBus := bus.New(nil, nil)
	healthMgr := health.New(cb)

	reg := resources.NewRegistry()

	abuse := abuseipdb.NewClient("fake", hc)

	// Ownership
	or := ownership.NewResolver()
	or.RegisterDomain(ownership.OwnershipDomain{ID: "cf-sync", Priority: 80, Capabilities: []ownership.Right{ownership.RightUpdate}})

	// Mock Policy Engine
	eng := polengine.New([]polmodels.Policy{})

	// Mock OPA
	ctx := context.Background()
	oe, _ := opa.NewEngine(ctx, slog.Default(), "package cfsync.admission\ndefault decision = \"allow\"")

	// Mock Federation
	fr := federation.NewResolver()

	rec := recorder.New(jsonlJournal, slog.Default())
	adm := admission.New(eng, oe, or, fr, rec, slog.Default())

	// Coordination, Lifecycle & Drift
	lm := coordination.NewLeaseManager(stateStore, time.Minute)
	sm := rtengine.NewStateMachine(stateStore, slog.Default())
	dm := driftmemory.NewStore()
	de := drift.NewEngine(reg, sm, dm, slog.Default())
	gv := governor.New(slog.Default())

	// Register provider in governor to avoid "budget exceeded" by default
	gv.RegisterProvider("cloudflare", map[governor.ResourceType]governor.Limit{
		governor.ResourceRequest: {MaxBurst: 100, Rate: 100, Interval: time.Hour},
	})

	// Convergence
	inv := invariants.New()
	cv := convergence.NewValidator(inv, slog.Default())

	// Rollback components
	rolp := rolplanner.New()
	role := rolexecutor.New(nil, jsonlJournal, cb, nil, nil)

	return pipeline.NewOrchestrator(cf, abuse, reconciliation.NewGenericPlanner(), translator.New(), validation.New(), adm, lm, sm, de, gv, cv, inv, rolp, role, jsonlJournal, stateStore, cb, eventBus, healthMgr, "")
}
