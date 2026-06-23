package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	abtransport "github.com/jm/security-automation-go/internal/abuseipdb/transport"
	abadapter "github.com/jm/security-automation-go/internal/adapters/abuseipdb"
	"github.com/jm/security-automation-go/internal/buildmeta"
	cfpkg "github.com/jm/security-automation-go/internal/cloudflare"
	"github.com/jm/security-automation-go/internal/cloudflare/mutate"
	"github.com/jm/security-automation-go/internal/cloudflare/resources"
	"github.com/jm/security-automation-go/internal/cloudflare/transport"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/crowdsec/translator"
	"github.com/jm/security-automation-go/internal/crowdsec/validation"
	"github.com/jm/security-automation-go/internal/execution"
	"github.com/jm/security-automation-go/internal/observability/tracing"
	"github.com/jm/security-automation-go/internal/orchestrator/pipeline"
	"github.com/jm/security-automation-go/internal/policy/admission"
	"github.com/jm/security-automation-go/internal/policy/bundles/activation"
	"github.com/jm/security-automation-go/internal/policy/bundles/registry"
	"github.com/jm/security-automation-go/internal/policy/bundles/trust"
	polcompiler "github.com/jm/security-automation-go/internal/policy/compiler"
	polengine "github.com/jm/security-automation-go/internal/policy/engine"
	"github.com/jm/security-automation-go/internal/policy/federation"
	"github.com/jm/security-automation-go/internal/policy/opa"
	"github.com/jm/security-automation-go/internal/policy/replay/recorder"
	"github.com/jm/security-automation-go/internal/reconciliation"
	rolexecutor "github.com/jm/security-automation-go/internal/rollback/executor"
	rolplanner "github.com/jm/security-automation-go/internal/rollback/planner"
	"github.com/jm/security-automation-go/internal/runtime/bus"
	"github.com/jm/security-automation-go/internal/runtime/checkpoint"
	"github.com/jm/security-automation-go/internal/runtime/convergence"
	"github.com/jm/security-automation-go/internal/runtime/cooldown"
	"github.com/jm/security-automation-go/internal/runtime/coordination"
	"github.com/jm/security-automation-go/internal/runtime/drift"
	driftmemory "github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/events"
	"github.com/jm/security-automation-go/internal/runtime/governor"
	"github.com/jm/security-automation-go/internal/runtime/health"
	"github.com/jm/security-automation-go/internal/runtime/invariants"
	"github.com/jm/security-automation-go/internal/runtime/lock"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/quarantine"
	stateful_scheduler "github.com/jm/security-automation-go/internal/runtime/scheduler/stateful"
	"github.com/jm/security-automation-go/internal/runtime/simulation"
	"github.com/jm/security-automation-go/internal/runtime/status"
	"github.com/jm/security-automation-go/internal/runtime/timeline"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/startuplog"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
	"github.com/jm/security-automation-go/internal/trustednetworks"
)

func runCFSync(configPath, mode string, dryRun bool, format string, metricsAddr string, args []string) {
	if err := config.LoadEnvFile(config.DefaultEnvFile); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not read %s: %v\n", config.DefaultEnvFile, err)
	}
	build := buildmeta.Current()
	cfg, err := config.Load(configPath)
	if err != nil {
		if configPath != "" {
			fmt.Fprintf(os.Stderr, "Error: failed to load configuration %q: %v\n", configPath, err)
		} else {
			fmt.Fprintf(os.Stderr, "Error: failed to load configuration: %v\n", err)
		}
		os.Exit(1)
	}

	// Admin commands need only the database — short-circuit before the full orchestrator.
	if mode == "admin" {
		runAdminCLI(context.Background(), cfg.StateDir, args)
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
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

	startLogger, startLogErr := startuplog.New(startuplog.DefaultLogDir)
	if startLogErr != nil {
		fmt.Fprintf(os.Stderr, "Warning: startup logging unavailable: %v\n", startLogErr)
	}
	defer startLogger.Close()
	startLogger.WriteStartup(startuplog.StartupInfo{
		Mode:       mode,
		ConfigFile: configPath,
		DBPath:     cfg.StateDir,
		DryRun:     dryRun,
	})

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: mapLogLevel(cfg.Global.Log.Level)}))

	// Acquire global instance lock for daemon or ui modes.
	var locker *lock.FileLock
	if mode == "daemon" || mode == "ui" {
		lockFile := filepath.Join(cfg.StateDir, "security-automation-go.pid")
		var err error
		locker, err = lock.NewFileLock(lockFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: failed to create lock: %v\n", err)
			os.Exit(1)
		}
		if err := locker.Acquire(); err != nil {
			if lockErr, ok := err.(lock.PIDLockedError); ok {
				fmt.Fprintf(os.Stderr, "Error: another instance (PID %d) is running\n", lockErr.PID)
			} else {
				fmt.Fprintf(os.Stderr, "Error: failed to acquire lock: %v\n", err)
			}
			os.Exit(1)
		}
		defer locker.Release()
		logger.Info("global instance lock acquired", "lock_file", lockFile)
	}

	if mode == "ui" {
		cfg.UI.Enabled = true // Force enable
	}

	// Open the main DB before launching the UI goroutine so both share a single connection
	// pool against runtime.db and migrations never run concurrently in the same process.
	bootstrapDB, err := sqlite.New(cfg.StateDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer bootstrapDB.Close()
	setupStore := sqlite.NewSetupStore(bootstrapDB)
	credentialStore := sqlite.NewCredentialStore(bootstrapDB)

	// Always start UI server in background if enabled.
	evidenceHolder := &lazyEvidenceStore{}
	// banLifecycleHolder is populated below once the scoped runtime DB is
	// opened (see initSQLite call further down). The UI goroutine starts
	// before scope resolution, so it must hold this indirection rather than
	// a *sqlite.BanLifecycleStore bound to the unscoped bootstrapDB.
	banLifecycleHolder := &lazyBanLifecycleStore{}
	// crowdSecStatusHolder is populated below once the scoped runtime DB is
	// opened. The root-owned cf-allowlist-sync helper writes its reconcile
	// status to that same scoped DB (see cmd/cf-allowlist-sync), so the UI
	// must read from it rather than the unscoped bootstrapDB.
	crowdSecStatusHolder := &lazyCrowdSecStatusStore{}
	// banDebannerHolder is populated below once the cleanup worker is wired
	// (same point as banLifecycleHolder/crowdSecStatusHolder), so the UI's
	// operator-initiated deban/clear actions become available without the UI
	// goroutine needing to know about cfEnforcer or the scoped DB directly.
	banDebannerHolder := &lazyBanDebanner{}
	// trustedNetworksCache is created here (before the UI goroutine starts)
	// and shared with the daemon's sync loop below, so the UI can render the
	// most recent SyncReport even though the registry itself is built later
	// in this function.
	trustedNetworksCache := trustednetworks.NewReportCache()
	if cfg.UI.Enabled {
		uiCfg := *cfg // snapshot: runUIWithLocker writes its own credential fields; avoid race with writes below
		go func() {
			if err := runUIWithLocker(ctx, logger, &uiCfg, false, evidenceHolder, bootstrapDB, trustedNetworksCache, banLifecycleHolder, crowdSecStatusHolder, banDebannerHolder); err != nil {
				logger.Error("UI server failed", "error", err)
			}
		}()
	}

	// If in UI mode and setup is not yet complete, wait for operator.
	if mode == "ui" {
		complete, _ := setupStore.IsComplete(ctx)
		if !complete {
			logger.Info("first-run setup wizard active on port 9091 — complete setup to enable automation")
			// Wait for interrupt or context cancellation
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
			select {
			case sig := <-sigChan:
				logger.Info("received signal, shutting down wizard", "signal", sig)
			case <-ctx.Done():
			}
			return
		}
		logger.Info("setup complete — starting background orchestration alongside UI")
	}

	if v, ok, _ := setupStore.GetSetting(ctx, "cf_zone_id"); ok && strings.TrimSpace(v) != "" {
		cfg.Cloudflare.ZoneID = v
	}
	if v, ok, _ := setupStore.GetSetting(ctx, "crowdsec_lapi_url"); ok && strings.TrimSpace(v) != "" {
		cfg.CrowdSec.PollerLAPIURL = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "cloudflare.api_token"); ok {
		cfg.Cloudflare.APIToken = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "abuseipdb.api_key"); ok {
		cfg.AbuseIPDB.APIKey = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "betterstack.source_token"); ok {
		cfg.BetterStack.SourceToken = v
	}
	// One-time migration: old uppercase credential key names → dotted convention.
	// Copies the old value to the new name if the new name is not yet present;
	// the old entry is left in place to avoid data loss.
	for _, m := range []struct{ old, newName string }{
		{"SPAMHAUS_API_KEY", "spamhaus.api_key"},
		{"VIRUSTOTAL_API_KEY", "virustotal.api_key"},
		{"ABUSEIPDB_KEY", "abuseipdb.api_key"},
	} {
		if old, ok, _ := credentialStore.Lookup(ctx, m.old); ok && old != "" {
			if _, exists, _ := credentialStore.Lookup(ctx, m.newName); !exists {
				_ = credentialStore.Set(ctx, m.newName, old, true)
			}
		}
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "spamhaus.api_key"); ok {
		cfg.Spamhaus.APIKey = v
	}
	if v, ok, _ := credentialStore.Lookup(ctx, "virustotal.api_key"); ok {
		cfg.VirusTotal.APIKey = v
	}

	// Apply runtime feature flags from SQLite (single source of truth post env-elimination).
	if rflags, err := setupStore.GetRuntimeFlags(ctx); err == nil {
		if rflags.CSPollerEnabled {
			cfg.CrowdSec.PollerEnabled = true
		}
		if rflags.CloudflareMutationsEnabled {
			cfg.Cloudflare.MutationsEnabled = true
		}
		if rflags.AbuseIPDBEnabled {
			cfg.AbuseIPDB.Enabled = true
		}
		if rflags.AutoBanEnabled {
			cfg.Cloudflare.AutoBanEnabled = true
		}
	} else {
		logger.Warn("could not read runtime flags from SQLite — using config/env defaults", "error", err)
	}

	hc := initHTTPClient(cfg)
	abuse, cf, betterClient := initExternalClients(cfg, hc)

	planner := reconciliation.NewGenericPlanner()
	trans := translator.New()
	val := validation.New()
	reg := resources.NewRegistry()

	currentScope, scopeDir := initRuntimeScope(cfg, logger)
	stateStore, jsonlJournal, cb := initScopedState(scopeDir)
	configureQuotaObservability(jsonlJournal)
	sqliteDB, eventStore, reportingStores, ownershipRepo, leaseRepo, cursorStore, err := initSQLite(scopeDir, currentScope.ID())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	defer sqliteDB.Close()
	evidenceHolder.set(reportingStores.Evidence)

	outboxLeaseGuard := reporting.NewLeaseStoreOutboxGuard(currentScope.ID(), "reconcile", leaseRepo)
	newBus := events.NewBus(eventStore, logger)
	eventBus := bus.New(logger, newBus)
	checkpointManager := checkpoint.NewManager(eventStore, eventStore, logger, 10, checkpoint.WithArchiveCompactor(eventStore))

	healthMgr := health.New(cb)
	qStore := quarantine.New(filepath.Join(scopeDir, "quarantine"))
	cooldownMgr := cooldown.NewManager(stateStore)

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
	ownerRes.SetLineageRecorder(sqlite.NewOwnershipLineageRecorder(ownershipRepo))
	ownerRes.SetClaimStore(ownershipRepo)

	pEngine := polengine.New(buildPolicies(cfg))
	intentComp := polcompiler.New()

	regoLoader := opa.NewBundleLoader(filepath.Join("internal", "policy", "rego"))
	regoCode, err := regoLoader.LoadDefault()
	if err != nil {
		logger.Warn("failed to load default rego policy", "error", err)
		regoCode = "package cfsync.admission\ndefault decision = \"allow\""
	}
	opaEng, err := opa.NewEngine(ctx, logger, regoCode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: failed to initialize OPA engine for scope %q: %v\n", currentScope.ID(), err)
		os.Exit(1)
	}

	evidenceRecorder := recorder.New(jsonlJournal, logger)
	trustStore := trust.NewStore()
	bundleReg := registry.New()
	activationMgr := activation.NewManager(bundleReg, trustStore)
	fedRes := federation.NewResolver()
	admController := admission.New(pEngine, opaEng, ownerRes, fedRes, evidenceRecorder, logger)

	leaseMgr := coordination.NewLeaseManager(stateStore, 10*time.Minute).WithLeaseStore(currentScope.ID(), leaseRepo)
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

	gov.RegisterProvider("cloudflare", map[governor.ResourceType]governor.Limit{
		governor.ResourceRequest:  {MaxBurst: 50, Rate: 10, Interval: time.Minute},
		governor.ResourceMutation: {MaxBurst: 10, Rate: 5, Interval: time.Minute},
	})

	cfTransport := transport.New(hc, cfg.Cloudflare.APIToken)
	govExec := execution.NewGovernedExecutor(jsonlJournal, cb, reg)
	var preBanTransport *abtransport.Transport
	if cfg.AbuseIPDB.APIKey != "" {
		preBanTransport = abtransport.New(hc, cfg.AbuseIPDB.APIKey)
	}
	trustRegistry := buildTrustRegistry(cfg)
	var preBanChecker *abadapter.Checker
	if preBanTransport != nil {
		preBanChecker = abadapter.NewChecker(preBanTransport, abadapter.Config{TTL: cfg.AbuseIPDB.CacheTTL, Timeout: cfg.AbuseIPDB.RequestTimeout})
	}
	securityTelemetry := newSecurityTelemetry(cfg, betterClient)
	quotaRefreshers := newQuotaRefreshers(cfg, hc, cf, preBanTransport, credentialStore, setupStore)
	abuseExecutor := newRuntimeAbuseExecutor(hc, credentialStore, setupStore, cfg != nil && cfg.AbuseIPDB.Enabled, abuse)
	outboxCfg := reporting.OutboxWorkerConfig{
		Limit:    25,
		Interval: cfg.Interval,
	}
	if cfg.Runtime.Profile == config.RuntimeProfileStrictHA {
		// In strict-HA mode, the outbox worker must hold a reconcile lease before
		// dispatching reports to prevent split-brain duplicate submissions.
		// In single-node mode, no second writer exists so the guard is omitted.
		outboxCfg.LeaseGuard = outboxLeaseGuard
	}
	var outboxWorker *reporting.OutboxWorker
	outboxWorker = reporting.NewOutboxWorker(reportingStores.Outbox, abuseExecutor, reportingStores.Dedup, reportingStores.Evidence, securityTelemetry, outboxCfg)
	configureSecurityGuard(govExec, preBanChecker, trustRegistry, cfg)
	govExec.SetTelemetrySink(securityTelemetry)
	govExec.SetApprovalEvidenceStore(sqlite.NewApprovalEvidenceStore(sqliteDB))
	govExec.SetFencingValidator(execution.NewLeaseStoreFencingValidator(leaseRepo).RequireFencing(true))
	mutate.RegisterAll(govExec, cfTransport, cfg.Cloudflare.ZoneID, "")

	rollbackPlanner := rolplanner.New()
	rollbackExecutor := rolexecutor.New(govExec.GetMutators(), jsonlJournal, cb, execution.NewDriftValidator(), execution.NewOwnershipValidator(reg))
	rollbackExecutor.SetFencingValidator(execution.NewLeaseStoreFencingValidator(leaseRepo).RequireFencing(true))
	rollbackExecutor.SetCheckpointStore(sqlite.NewRollbackCheckpointStore(sqliteDB))

	collector := status.NewCollector(build.Version, time.Now(), healthMgr, cb, stateStore, filepath.Join(scopeDir, "daemon.lock"), filepath.Join(scopeDir, "quarantine"))
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

	if mode == "daemon" || mode == "ui" {
		banLifecycleStore := sqlite.NewBanLifecycleStore(sqliteDB)
		banLifecycleHolder.set(banLifecycleStore)
		crowdSecStatusHolder.set(sqlite.NewCrowdSecAllowlistStatusStore(sqliteDB))
		bundle := newWAFBundle(cf, abuse, hc, credentialStore, setupStore, securityTelemetry, trustRegistry, cfg, reportingStores, banLifecycleStore, logger)
		var cfEnforcer cfpkg.EnforcementClient
		if cfg.Cloudflare.MutationsEnabled && cfg.Cloudflare.APIToken != "" {
			cfEnforcer = cfpkg.NewClient(hc, cfg.Cloudflare.APIToken)
		}
		trustedNetworksStore := sqlite.NewTrustedNetworksStore(sqliteDB)
		seedTrustedNetworksFromASN(ctx, trustedNetworksStore, logger)
		trustedNetworksReg := buildTrustedNetworksRegistry(cfg, trustedNetworksStore, cfEnforcer, jsonlJournal, logger, trustedNetworksCache)
		runDaemonWithLocker(ctx, logger, orch, collector, jsonlJournal, qStore, stateStore, sm, driftMem, cooldownMgr, evidenceRecorder, bundleReg, activationMgr, fedRes, admController, reportingStores.Evidence, ownershipRepo, s.GetPool(), outboxWorker, scopeDir, cfg.Interval, metricsAddr, cfg.Cloudflare.ZoneID, bundle.cfWAFService(), cursorStore, quotaRefreshers, bundle, false, cfEnforcer, cfg.Cloudflare.CleanupInterval, cfg, trustRegistry, trustedNetworksReg, banDebannerHolder)
		// In ui mode the HTTP server runs in a goroutine above. If runDaemonWithLocker
		// returns early (e.g. API token not configured) while the context is still live,
		// keep the process alive so the UI goroutine can continue serving.
	} else if mode == "evidence" {
		runEvidenceCLI(ctx, reportingStores.Evidence, args, format)
	} else if mode == "ownership" {
		runOwnershipCLI(ctx, ownershipRepo, args, format)
	} else if mode == "doctor" {
		runDoctor(ctx, orch, stateStore, jsonlJournal)
	} else if mode == "status" {
		runStatus(collector, format)
	} else {
		runCLI(ctx, orch, cfg.Cloudflare.ZoneID, dryRun, format)
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
