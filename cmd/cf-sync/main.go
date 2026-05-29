package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jm/security-automation-go/internal/abuseipdb"
	abtransport "github.com/jm/security-automation-go/internal/abuseipdb/transport"
	abadapter "github.com/jm/security-automation-go/internal/adapters/abuseipdb"
	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/betterstack"
	"github.com/jm/security-automation-go/internal/cloudflare/client"
	"github.com/jm/security-automation-go/internal/cloudflare/mutate"
	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec/dryrun"
	"github.com/jm/security-automation-go/internal/crowdsec/translator"
	"github.com/jm/security-automation-go/internal/crowdsec/validation"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/httpclient"
	"github.com/jm/security-automation-go/internal/observability/tracing"
	"github.com/jm/security-automation-go/internal/orchestrator/pipeline"
	"github.com/jm/security-automation-go/internal/policy/admission"
	"github.com/jm/security-automation-go/internal/policy/bundles/activation"
	"github.com/jm/security-automation-go/internal/policy/bundles/registry"
	"github.com/jm/security-automation-go/internal/policy/bundles/trust"
	polcompiler "github.com/jm/security-automation-go/internal/policy/compiler"
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
	"github.com/jm/security-automation-go/internal/runtime/checkpoint"
	"github.com/jm/security-automation-go/internal/runtime/convergence"
	"github.com/jm/security-automation-go/internal/runtime/cooldown"
	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/diagnostics"
	"github.com/jm/security-automation-go/internal/runtime/drift"
	driftmemory "github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/health"
	"github.com/jm/security-automation-go/internal/runtime/invariants"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/lock"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/quarantine"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/pool"
	stateful_scheduler "github.com/jm/security-automation-go/internal/runtime/scheduler/stateful"
	"github.com/jm/security-automation-go/internal/runtime/scope"
	"github.com/jm/security-automation-go/internal/runtime/simulation"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/runtime/status"
	"github.com/jm/security-automation-go/internal/runtime/timeline"
	sectrust "github.com/jm/security-automation-go/internal/security/trust"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/snapshot"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/testing/chaos"
	"github.com/jm/security-automation-go/internal/testing/chaos/scenarios"
)

func main() {
	configPath := flag.String("config", "", "Path to YAML config file")
	mode := flag.String("mode", "cli", "Execution mode (cli|daemon|doctor|status)")
	dryRun := flag.Bool("dry-run", true, "Execute in dry-run mode (default true)")
	format := flag.String("format", "text", "Output format (text|json)")
	metricsAddr := flag.String("metrics-addr", ":9090", "Address to expose Prometheus metrics")
	flag.Parse()

	// 1. Load robust configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Printf("Error: Failed to load configuration: %v\n", err)
		os.Exit(1)
	}

	// 2. Initialize Tracing
	ctx := context.Background()
	otelShutdown, err := tracing.InitTracer(ctx, tracing.Config{
		Enabled:      cfg.Global.Tracing.Enabled,
		ServiceName:  cfg.Global.ServiceName,
		Exporter:     cfg.Global.Tracing.Exporter,
		Endpoint:     cfg.Global.Tracing.Endpoint,
		Insecure:     cfg.Global.Tracing.Insecure,
		SamplingRate: cfg.Global.Tracing.SamplingRate,
	})
	if err != nil {
		fmt.Printf("Warning: Failed to initialize tracing: %v\n", err)
	}
	defer otelShutdown(ctx)

	// 3. Initialize global dependencies
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: mapLogLevel(cfg.Global.Log.Level),
	}))
	hc := httpclient.New(cfg.Global.HTTP)
	cf := client.New(cfg.Cloudflare.APIToken, hc)

	var abuse *abuseipdb.Client
	if cfg.AbuseIPDB.APIKey != "" && !abuseIPDBReportingDisabled(cfg) {
		abuse = abuseipdb.NewClient(cfg.AbuseIPDB.APIKey, hc)
	}

	planner := reconciliation.NewGenericPlanner()
	trans := translator.New()
	val := validation.New()
	reg := resources.NewRegistry()

	// 4. Define current scope (Partitioning)
	currentScope := scope.RuntimeScope{
		Tenant:      cfg.Global.ServiceName,
		AccountID:   "shared",
		ZoneID:      cfg.Cloudflare.ZoneID,
		Environment: "production",
	}
	scopeDir := filepath.Join(cfg.StateDir, currentScope.ID())
	_ = os.MkdirAll(scopeDir, 0755)

	logger.Info("runtime scope initialized",
		"scope_id", currentScope.ID(),
		"scope_name", currentScope.String(),
		"scope_dir", scopeDir,
	)

	// 5. Scoped Runtime components
	journalPath := filepath.Join(scopeDir, "audit.jsonl")
	stateStore := state.NewStateStore(scopeDir)
	jsonlJournal := journal.NewJSONLJournal(journalPath)
	cb := breaker.New(5, 5*time.Minute, 1*time.Minute)

	// SQLite and Event Sourcing
	sqliteDB, err := sqlite.New(scopeDir)
	if err != nil {
		fmt.Printf("Error: Failed to initialize SQLite database: %v\n", err)
		os.Exit(1)
	}
	defer sqliteDB.Close()

	eventStore := sqlite.NewEventRepository(sqliteDB)
	reportingStores := sqlite.NewReportingStores(sqliteDB)
	cursorStore := reportingStores.Cursors
	outboxLeaseGuard := reporting.NewLeaseStoreOutboxGuard(currentScope.ID(), "reconcile", sqlite.NewLeaseRepository(sqliteDB))
	newBus := events.NewBus(eventStore, logger)
	eventBus := bus.New(logger, newBus)
	checkpointManager := checkpoint.NewManager(eventStore, eventStore, logger, 10)

	healthMgr := health.New(cb)
	qStore := quarantine.New(filepath.Join(scopeDir, "quarantine"))
	cooldownMgr := cooldown.NewManager(stateStore)

	// 6. Ownership Federation
	ownerRes := ownership.NewResolver()
	ownerRes.RegisterDomain(ownership.OwnershipDomain{
		ID:           "terraform",
		Type:         ownership.DomainTerraform,
		Priority:     100,
		Trust:        ownership.TrustAuthoritative,
		Capabilities: []ownership.Right{ownership.RightCreate, ownership.RightUpdate, ownership.RightDelete, ownership.RightRollback, ownership.RightOverride},
	})
	ownerRes.RegisterDomain(ownership.OwnershipDomain{
		ID:           "cf-sync",
		Type:         ownership.DomainCFSync,
		Priority:     80,
		Trust:        ownership.TrustManaged,
		Capabilities: []ownership.Right{ownership.RightCreate, ownership.RightUpdate, ownership.RightDelete, ownership.RightRollback},
	})
	ownershipRepo := sqlite.NewOwnershipRepository(sqliteDB)
	ownerRes.SetLineageRecorder(sqlite.NewOwnershipLineageRecorder(ownershipRepo))
	ownerRes.SetClaimStore(ownershipRepo)

	// 7. Policy Engine
	var policies []polmodels.Policy
	for _, p := range cfg.Policies {
		policy := polmodels.Policy{
			ID:      p.ID,
			Name:    p.Name,
			Enabled: p.Enabled,
		}
		for _, r := range p.Rules {
			policy.Rules = append(policy.Rules, polmodels.Rule{
				ID:          r.ID,
				Description: r.Description,
				Target:      r.Target,
				Condition:   r.Condition,
				Decision:    polmodels.Decision(r.Decision),
			})
		}
		policies = append(policies, policy)
	}
	pEngine := polengine.New(policies)
	intentComp := polcompiler.New()

	// 7a. OPA Policy Engine & Evidence Recorder
	regoLoader := opa.NewBundleLoader(filepath.Join("internal", "policy", "rego"))
	regoCode, err := regoLoader.LoadDefault()
	if err != nil {
		logger.Warn("failed to load default rego policy", "error", err)
		regoCode = "package cfsync.admission\ndefault decision = \"allow\"" // Emergency fallback
	}
	opaEng, err := opa.NewEngine(ctx, logger, regoCode)
	if err != nil {
		fmt.Printf("Error: Failed to initialize OPA engine: %v\n", err)
		os.Exit(1)
	}

	evidenceRecorder := recorder.New(jsonlJournal, logger)

	// 7b. Trusted Bundles & Trust Store
	trustStore := trust.NewStore()
	// TODO: Register trusted keys from config
	bundleReg := registry.New()
	activationMgr := activation.NewManager(bundleReg, trustStore)

	// 7c. Policy Federation
	fedRes := federation.NewResolver()

	admController := admission.New(pEngine, opaEng, ownerRes, fedRes, evidenceRecorder, logger)

	// 8. Coordination, Lifecycle, Drift, Governor & Rollback Engine
	leaseMgr := coordination.NewLeaseManager(stateStore, 10*time.Minute).WithLeaseStore(currentScope.ID(), sqlite.NewLeaseRepository(sqliteDB))
	sm := engine.NewStateMachine(stateStore, logger)
	sm.SetEventBus(newBus)
	sm.SetCheckpointManager(checkpointManager)
	driftMem := driftmemory.NewStore()
	driftEng := drift.NewEngine(reg, sm, driftMem, logger)
	gov := governor.New(logger)
	invEng := invariants.New()
	convVal := convergence.NewValidator(invEng, logger)
	simEng := simulation.NewEngine()
	tlCollector := timeline.NewCollector(eventStore)

	// Register default Cloudflare limits
	gov.RegisterProvider("cloudflare", map[governor.ResourceType]governor.Limit{
		governor.ResourceRequest:  {MaxBurst: 50, Rate: 10, Interval: time.Minute},
		governor.ResourceMutation: {MaxBurst: 10, Rate: 5, Interval: time.Minute},
	})

	cfTransport := transport.New(hc, cfg.Cloudflare.APIToken)
	govExec := execution.NewGovernedExecutor(jsonlJournal, cb, reg)
	preBanTransport := abtransport.New(hc, cfg.AbuseIPDB.APIKey)
	trustRegistry := sectrust.DefaultRegistry()
	preBanChecker := abadapter.NewChecker(preBanTransport, abadapter.Config{
		TTL:     cfg.AbuseIPDB.CacheTTL,
		Timeout: cfg.AbuseIPDB.RequestTimeout,
	})
	betterClient := betterstack.NewClient(hc, cfg.BetterStack.SourceToken, cfg.BetterStack.IngestingHost)
	securityTelemetry := newSecurityTelemetry(cfg, betterClient)
	var outboxWorker *reporting.OutboxWorker
	if abuse != nil {
		outboxWorker = reporting.NewOutboxWorker(reportingStores.Outbox, abuse.Executor, reportingStores.Dedup, reportingStores.Evidence, securityTelemetry, reporting.OutboxWorkerConfig{
			Limit:      25,
			LeaseGuard: outboxLeaseGuard,
		})
	}
	configureSecurityGuard(govExec, preBanChecker, trustRegistry, cfg)
	govExec.SetTelemetrySink(securityTelemetry)
	govExec.SetApprovalEvidenceStore(sqlite.NewApprovalEvidenceStore(sqliteDB))
	govExec.SetFencingValidator(execution.NewLeaseStoreFencingValidator(sqlite.NewLeaseRepository(sqliteDB)).RequireFencing(true))
	mutate.RegisterAll(govExec, cfTransport, cfg.Cloudflare.ZoneID, "")

	rollbackPlanner := rolplanner.New()
	rollbackExecutor := rolexecutor.New(govExec.GetMutators(), jsonlJournal, cb, execution.NewDriftValidator(), execution.NewOwnershipValidator(reg))
	rollbackExecutor.SetFencingValidator(execution.NewLeaseStoreFencingValidator(sqlite.NewLeaseRepository(sqliteDB)).RequireFencing(true))
	rollbackExecutor.SetCheckpointStore(sqlite.NewRollbackCheckpointStore(sqliteDB))

	collector := status.NewCollector("v1.0.0", time.Now(), healthMgr, cb, stateStore, filepath.Join(scopeDir, "daemon.lock"), filepath.Join(scopeDir, "quarantine"))
	orch := pipeline.NewOrchestrator(cf, abuse, planner, trans, val, admController, leaseMgr, sm, driftEng, gov, convVal, invEng, rollbackPlanner, rollbackExecutor, jsonlJournal, stateStore, cb, eventBus, healthMgr, filepath.Join(scopeDir, "KILL_SWITCH"))

	s := stateful_scheduler.New(stateStore, orch, sm, cooldownMgr, logger, cfg.Interval)

	if err := validateStartupWiring(cfg, startupWiringInputs{
		executor:         govExec,
		rollback:         rollbackExecutor,
		leaseManager:     leaseMgr,
		auditJournal:     jsonlJournal,
		ownership:        ownerRes,
		policyEngine:     pEngine,
		opaEngine:        opaEng,
		governor:         gov,
		outboxWorker:     outboxWorker,
		outboxLeaseGuard: outboxLeaseGuard,
	}); err != nil {
		fmt.Printf("Error: Runtime startup validation failed: %v\n", err)
		os.Exit(1)
	}

	if *mode == "daemon" {
		wafReplay := newWAFReplayService(cf, abuse, securityTelemetry, trustRegistry, cfg, reportingStores)
		runDaemon(ctx, logger, orch, collector, jsonlJournal, qStore, stateStore, sm, driftMem, cooldownMgr, evidenceRecorder, bundleReg, activationMgr, fedRes, admController, reportingStores.Evidence, sqlite.NewOwnershipRepository(sqliteDB), s.GetPool(), scopeDir, cfg.Interval, *metricsAddr, cfg.Cloudflare.ZoneID, wafReplay, cursorStore)
	} else if *mode == "evidence" {
		runEvidenceCLI(ctx, reportingStores.Evidence, flag.Args(), *format)
	} else if *mode == "ownership" {
		runOwnershipCLI(ctx, sqlite.NewOwnershipRepository(sqliteDB), flag.Args(), *format)
	} else if *mode == "doctor" {
		runDoctor(ctx, orch, stateStore, jsonlJournal)
	} else if *mode == "status" {
		runStatus(collector, *format)
	} else {
		runCLI(ctx, orch, cfg.Cloudflare.ZoneID, *dryRun, *format)
	}

	_ = intentComp
	_ = simEng
	_ = tlCollector
}

func mapLogLevel(level string) slog.Level {
	switch strings.ToLower(level) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func runCLI(ctx context.Context, orch *pipeline.Orchestrator, zoneID string, dryRun bool, format string) {
	if orch.IsKilled() {
		fmt.Println("Error: Manual kill-switch is active. Mutations are disabled.")
	}

	prov := snapshot.ProvenanceMetadata{
		GeneratedBy: "cf-sync-cli",
		GeneratedAt: time.Now().UTC(),
	}

	res, err := orch.DryRun(ctx, zoneID, snapshot.ResourceIPAccessRules, prov)
	if err != nil {
		fmt.Printf("Pipeline failed: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
	} else {
		renderer := dryrun.New()
		fmt.Printf("Snapshot: %d objects, Checksum: %s\n", res.Snapshot.ObjectCount, res.Snapshot.Checksum)
		fmt.Printf("Plan: %d operations\n", res.Planning.OperationCount)
		fmt.Println(renderer.RenderText(res.Actions))
		if !dryRun {
			fmt.Println("Live execution not yet implemented in CLI.")
		}
	}
}

func runStatus(collector *status.Collector, format string) {
	res, err := collector.Collect()
	if err != nil {
		fmt.Printf("Error: Failed to collect status: %v\n", err)
		os.Exit(1)
	}

	if format == "json" {
		data, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(data))
		return
	}

	fmt.Println("=== cf-sync Runtime Status ===")
	fmt.Printf("Version:    %s\n", res.Version)
	fmt.Printf("Uptime:     %s (Started at %s)\n", res.Uptime, res.StartedAt.Format(time.RFC3339))
	fmt.Printf("Health:     %s (Consecutive Fails: %d)\n", res.Health.Status, res.Health.ConsecutiveFails)
	fmt.Printf("Breaker:    %s\n", res.Breaker.State)
	fmt.Printf("Lock:       Locked=%v\n", res.Lock.IsLocked)
	fmt.Printf("Quarantine: %d active items\n", res.Quarantine.ActiveItems)
	fmt.Printf("Last Sync:  %s\n", res.Reconciliation.LastSuccessAt)
	if res.Reconciliation.LastPlanID != "" {
		fmt.Printf("Last Plan:  %s\n", res.Reconciliation.LastPlanID)
	}
}

func runDoctor(ctx context.Context, orch *pipeline.Orchestrator, stateStore *state.StateStore, j journal.JournalStore) {
	fmt.Println("=== cf-sync doctor: System Consistency Check ===")

	events, _ := j.List()
	curState, _ := stateStore.Load()

	val := diagnostics.New()
	report := val.ValidateConsistency(events, curState)

	fmt.Printf("Journal Entries: %d\n", report.JournalEntries)
	fmt.Printf("Healthy:         %v\n", report.Healthy)

	if !report.Healthy {
		fmt.Printf("Issues Detected:\n")
		for _, issue := range report.IncompleteRuns {
			fmt.Printf("- Incomplete Run: %s\n", issue)
		}
	}

	fmt.Println("\n=== Running Chaos Engineering Suite ===")
	runner := chaos.NewRunner(orch)
	chaosReport := runner.RunSuite(ctx, scenarios.GetInitialScenarios())
	fmt.Println(chaosReport.String())
}

func runDaemon(ctx context.Context, logger *slog.Logger, orch *pipeline.Orchestrator, collector *status.Collector, j journal.JournalStore, qStore *quarantine.Store, store *state.StateStore, sm *engine.StateMachine, dm *driftmemory.Store, cm *cooldown.Manager, rec *recorder.Recorder, br *registry.Registry, am *activation.Manager, fr *federation.Resolver, adm *admission.Controller, evidence reporting.EvidenceStore, ownershipRepo *sqlite.OwnershipRepository, p *pool.Pool, stateDir string, interval time.Duration, metricsAddr string, zoneID string, wafReplay *cloudflareevent.Service, cursorStore *sqlite.CursorStore) {
	logger.Info("starting in daemon mode", "state_dir", stateDir, "interval", interval, "metrics_addr", metricsAddr)

	var ownershipLineage *ownership.LineageQueryService
	if ownershipRepo != nil {
		ownershipLineage = ownership.NewLineageQueryService(ownershipRepo)
	}
	srv := startAPIServer(logger, collector, j, qStore, orch, p, sm, dm, rec, br, am, fr, adm, evidence, ownershipLineage, metricsAddr)

	l := lock.NewFileLock(stateDir)
	s := stateful_scheduler.New(store, orch, sm, cm, logger, interval)

	// Handle graceful shutdown
	childCtx, cancel := newDaemonContext(ctx, logger, srv)
	defer cancel()
	startWAFReplayPoller(childCtx, logger, interval, zoneID, wafReplay, cursorStore)

	// Note: We'll wrap the scheduler Start in the lock check
	// for full split-brain safety in daemon mode.
	acquired, err := l.Acquire()
	if err != nil {
		logger.Error("failed to acquire daemon lock", "error", err)
		os.Exit(1)
	}
	if !acquired {
		logger.Error("failed to acquire daemon lock: another instance is running")
		os.Exit(1)
	}
	defer l.Release()

	if err := s.Start(childCtx, os.Getenv("CF_ZONE_ID")); err != nil {
		logger.Error("daemon error", "error", err)
		os.Exit(1)
	}
}
