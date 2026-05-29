package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/execution"
	rolexecutor "github.com/jm/security-automation-go/internal/rollback/executor"
	"github.com/jm/security-automation-go/internal/runtime/breaker"
	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/runtime/wiring"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/telemetry/sinks"
)

func TestRuntimeWiringInvariants(t *testing.T) {
	matrix := wiring.Matrix{
		Profile:                      config.RuntimeProfileStrictHA,
		Fencing:                      true,
		Lease:                        true,
		LeaderCoordination:           true,
		Audit:                        true,
		Telemetry:                    true,
		Ownership:                    true,
		PolicyEngine:                 true,
		Governor:                     true,
		OPA:                          true,
		OutboxWorker:                 true,
		OutboxLeaseGuard:             true,
		AbuseIPDBReportingConfigured: true,
		AbuseIPDBReportingEnabled:    true,
	}
	if err := matrix.ValidateStartup(); err != nil {
		t.Fatalf("expected complete strict-ha wiring to pass: %v", err)
	}
}

func TestStrictHAStartupSuccess(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Runtime.Profile = config.RuntimeProfileStrictHA
	cfg.AbuseIPDB.ReportingEnabled = boolPtr(true)

	tmp := t.TempDir()
	jsonlJournal := journal.NewJSONLJournal(filepath.Join(tmp, "audit.jsonl"))
	cb := breaker.New(5, time.Minute, time.Minute)
	reg := resources.NewRegistry()
	exec := execution.NewGovernedExecutor(jsonlJournal, cb, reg)
	db, err := sqlite.New(tmp)
	if err != nil {
		t.Fatalf("sqlite: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	leases := sqlite.NewLeaseRepository(db)
	exec.SetFencingValidator(execution.NewLeaseStoreFencingValidator(leases).RequireFencing(true))
	exec.SetTelemetrySink(sinks.NewMulti(sinks.NewPrometheus()))
	rollback := rolexecutor.New(exec.GetMutators(), jsonlJournal, cb, execution.NewDriftValidator(), execution.NewOwnershipValidator(reg))
	rollback.SetFencingValidator(execution.NewLeaseStoreFencingValidator(leases).RequireFencing(true))
	leaseManager := coordination.NewLeaseManager(state.NewStateStore(tmp), time.Minute).WithLeaseStore("scope-a", leases)
	outboxGuard := reporting.NewLeaseStoreOutboxGuard("scope-a", "reconcile", leases)
	outboxWorker := reporting.NewOutboxWorker(nil, nil, nil, nil, nil, reporting.OutboxWorkerConfig{LeaseGuard: outboxGuard})

	err = validateStartupWiring(cfg, startupWiringInputs{
		executor:         exec,
		rollback:         rollback,
		leaseManager:     leaseManager,
		auditJournal:     jsonlJournal,
		ownership:        struct{}{},
		policyEngine:     struct{}{},
		opaEngine:        struct{}{},
		governor:         struct{}{},
		outboxWorker:     outboxWorker,
		outboxLeaseGuard: outboxGuard,
	})
	if err != nil {
		t.Fatalf("expected strict-ha startup validation to pass: %v", err)
	}
}

func TestStrictHAStartupFailsIfMissingLeaseGuard(t *testing.T) {
	matrix := strictHAMatrix()
	matrix.OutboxLeaseGuard = false

	err := matrix.ValidateStartup()
	if err == nil {
		t.Fatal("expected strict-ha startup validation to fail without outbox lease guard")
	}
}

func TestStrictHAStartupFailsIfAbuseIPDBEnabledAndWorkerMissing(t *testing.T) {
	matrix := strictHAMatrix()
	matrix.OutboxWorker = false

	err := matrix.ValidateStartup()
	if err == nil {
		t.Fatal("expected strict-ha startup validation to fail without outbox worker")
	}
	assertErrorContains(t, err,
		"strict-ha requires outbox_worker",
		"because abuseipdb reporting is enabled",
		"Active config: runtime.profile=strict-ha, abuseipdb.reporting_enabled=true",
		"Configure AbuseIPDB client or disable reporting explicitly",
	)
}

func TestStrictHAStartupAllowsMissingWorkerWhenAbuseIPDBDisabled(t *testing.T) {
	matrix := strictHAMatrix()
	matrix.AbuseIPDBReportingEnabled = false
	matrix.OutboxWorker = false
	matrix.OutboxLeaseGuard = false

	if err := matrix.ValidateStartup(); err != nil {
		t.Fatalf("expected strict-ha startup validation to pass when AbuseIPDB reporting is explicitly disabled: %v", err)
	}
}

func TestStrictHAStartupFailsIfWorkerPresentButLeaseGuardMissing(t *testing.T) {
	matrix := strictHAMatrix()
	matrix.OutboxWorker = true
	matrix.OutboxLeaseGuard = false

	err := matrix.ValidateStartup()
	if err == nil {
		t.Fatal("expected strict-ha startup validation to fail without outbox lease guard")
	}
	assertErrorContains(t, err,
		"strict-ha requires outbox_lease_guard",
		"because abuseipdb reporting is enabled and retries must stop after lease loss",
		"Active config: runtime.profile=strict-ha, abuseipdb.reporting_enabled=true",
	)
}

func TestSingleNodeStartupAllowsMissingWorker(t *testing.T) {
	matrix := strictHAMatrix()
	matrix.Profile = config.RuntimeProfileSingleNode
	matrix.AbuseIPDBReportingConfigured = false
	matrix.AbuseIPDBReportingEnabled = false
	matrix.OutboxWorker = false
	matrix.OutboxLeaseGuard = false

	if err := matrix.ValidateStartup(); err != nil {
		t.Fatalf("expected single-node startup validation to pass without outbox worker: %v", err)
	}
}

func TestStrictHAStartupFailsIfAbuseIPDBReportingIntentMissing(t *testing.T) {
	matrix := strictHAMatrix()
	matrix.AbuseIPDBReportingConfigured = false
	matrix.AbuseIPDBReportingEnabled = false

	err := matrix.ValidateStartup()
	if err == nil {
		t.Fatal("expected strict-ha startup validation to fail without explicit AbuseIPDB reporting intent")
	}
	assertErrorContains(t, err,
		"strict-ha requires abuseipdb.reporting_enabled",
		"because reporting mode must be explicit",
		"Set abuseipdb.reporting_enabled to true or false",
	)
}

func TestStrictHAStartupFailsIfFencingAbsent(t *testing.T) {
	matrix := strictHAMatrix()
	matrix.Fencing = false

	err := matrix.ValidateStartup()
	if err == nil {
		t.Fatal("expected strict-ha startup validation to fail without fencing")
	}
}

func strictHAMatrix() wiring.Matrix {
	return wiring.Matrix{
		Profile:                      config.RuntimeProfileStrictHA,
		Fencing:                      true,
		Lease:                        true,
		LeaderCoordination:           true,
		Audit:                        true,
		Telemetry:                    true,
		Ownership:                    true,
		PolicyEngine:                 true,
		Governor:                     true,
		OPA:                          true,
		OutboxWorker:                 true,
		OutboxLeaseGuard:             true,
		AbuseIPDBReportingConfigured: true,
		AbuseIPDBReportingEnabled:    true,
	}
}

func assertErrorContains(t *testing.T, err error, parts ...string) {
	t.Helper()
	text := err.Error()
	for _, part := range parts {
		if !strings.Contains(text, part) {
			t.Fatalf("expected error to contain %q, got:\n%s", part, text)
		}
	}
}

func boolPtr(v bool) *bool {
	return &v
}
