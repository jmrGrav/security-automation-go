package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/jm/security-automation-go/internal/adapters/cloudflareevent"
	"github.com/jm/security-automation-go/internal/api/auth"
	"github.com/jm/security-automation-go/internal/api/server"
	"github.com/jm/security-automation-go/internal/config"
	"github.com/jm/security-automation-go/internal/observability/handlers"
	"github.com/jm/security-automation-go/internal/orchestrator/pipeline"
	"github.com/jm/security-automation-go/internal/policy/admission"
	"github.com/jm/security-automation-go/internal/policy/bundles/activation"
	"github.com/jm/security-automation-go/internal/policy/bundles/registry"
	"github.com/jm/security-automation-go/internal/policy/federation"
	"github.com/jm/security-automation-go/internal/policy/replay/recorder"
	"github.com/jm/security-automation-go/internal/runtime/cooldown"
	"github.com/jm/security-automation-go/internal/runtime/drift/memory"
	"github.com/jm/security-automation-go/internal/runtime/engine"
	"github.com/jm/security-automation-go/internal/runtime/journal"
	"github.com/jm/security-automation-go/internal/runtime/lock"
	"github.com/jm/security-automation-go/internal/runtime/ownership"
	"github.com/jm/security-automation-go/internal/runtime/quarantine"
	"github.com/jm/security-automation-go/internal/runtime/scheduler/pool"
	stateful_scheduler "github.com/jm/security-automation-go/internal/runtime/scheduler/stateful"
	"github.com/jm/security-automation-go/internal/runtime/state"
	"github.com/jm/security-automation-go/internal/runtime/status"
	"github.com/jm/security-automation-go/internal/services/reporting"
	"github.com/jm/security-automation-go/internal/storage/sqlite"
)

const cloudflareReplayOverlap = 10 * time.Minute

type cursorStateStore interface {
	Load(ctx context.Context, name string) (time.Time, bool, error)
	Save(ctx context.Context, name string, value time.Time) error
}

func newAuthenticator() (*auth.Authenticator, error) {
	token, err := config.ResolveAdminToken()
	if err != nil {
		return nil, fmt.Errorf("resolving admin token: %w", err)
	}
	authTokens := map[string]auth.Identity{
		token: {
			OperatorID: "admin",
			Scopes: []auth.Scope{
				auth.ScopeRuntimeRead,
				auth.ScopeRuntimeExecute,
				auth.ScopeRuntimeRollback,
				auth.ScopeQuarantineManage,
				auth.ScopeAuditRead,
			},
		},
	}
	return auth.NewAuthenticator(authTokens), nil
}

func startAPIServer(logger *slog.Logger, collector *status.Collector, j journal.JournalStore, qStore *quarantine.Store, orch *pipeline.Orchestrator, p *pool.Pool, sm *engine.StateMachine, dm *memory.Store, rec *recorder.Recorder, br *registry.Registry, am *activation.Manager, fr *federation.Resolver, adm *admission.Controller, evidence reporting.EvidenceStore, ownershipLineage *ownership.LineageQueryService, metricsAddr string) (*http.Server, error) {
	authenticator, err := newAuthenticator()
	if err != nil {
		return nil, err
	}
	apiSrv := server.New(
		logger,
		collector,
		j,
		qStore,
		orch.GetOwnershipResolver(),
		orch.GetGovernor(),
		p,
		sm,
		dm,
		rec,
		br,
		am,
		fr,
		adm,
		evidence,
		ownershipLineage,
		authenticator,
	)

	mux := http.NewServeMux()
	mux.Handle("/metrics", handlers.NewMetricsHandler())
	mux.Handle("/api/v1/", apiSrv.Handler())
	mux.Handle("/api/v2/", apiSrv.Handler())
	mux.Handle("/api/v3/", apiSrv.Handler())
	mux.Handle("/statusz", handlers.StatuszHandler(collector))
	mux.HandleFunc("/healthz", handlers.HealthzHandler)
	mux.HandleFunc("/readyz", handlers.ReadyzHandler)

	srv := &http.Server{
		Addr:    metricsAddr,
		Handler: mux,
	}
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Error("metrics server failed", "error", err)
		}
	}()
	return srv, nil
}

func newDaemonContext(ctx context.Context, logger *slog.Logger, srv *http.Server) (context.Context, context.CancelFunc) {
	childCtx, cancel := context.WithCancel(ctx)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("received signal, shutting down", "signal", sig)

		if srv != nil {
			shutdownCtx, shutCancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer shutCancel()
			_ = srv.Shutdown(shutdownCtx)
		}

		cancel()
	}()

	return childCtx, cancel
}

// startCrowdSecOpenRestyPoller starts a background goroutine that reads CrowdSec
// decisions and OpenResty Lua events on each interval tick and feeds them into
// the shared reporting service (evidence + AbuseIPDB outbox).
func startCrowdSecOpenRestyPoller(ctx context.Context, logger *slog.Logger, interval time.Duration, bundle *wafBundle) {
	if bundle == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			processCrowdSecOnce(ctx, logger, bundle)
			processOpenRestyOnce(ctx, logger, bundle)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func processCrowdSecOnce(ctx context.Context, logger *slog.Logger, bundle *wafBundle) {
	if bundle == nil || bundle.csSource == nil || bundle.cs == nil {
		return
	}
	events, err := bundle.csSource.Read(ctx)
	if err != nil {
		logger.WarnContext(ctx, "crowdsec live source read failed", "error", err)
		return
	}
	for _, event := range events {
		if _, err := bundle.cs.Process(ctx, event); err != nil {
			logger.WarnContext(ctx, "crowdsec event processing failed", "ip", event.IP, "rule_id", event.RuleID, "error", err)
		}
	}
	if len(events) > 0 {
		logger.Info("crowdsec waf events processed", "count", len(events))
	}
}

func processOpenRestyOnce(ctx context.Context, logger *slog.Logger, bundle *wafBundle) {
	if bundle == nil || bundle.orSource == nil || bundle.or == nil {
		return
	}
	events, err := bundle.orSource.Read(ctx)
	if err != nil {
		logger.WarnContext(ctx, "openresty live source read failed", "error", err)
		return
	}
	for _, event := range events {
		if _, err := bundle.or.Process(ctx, event); err != nil {
			logger.WarnContext(ctx, "openresty event processing failed", "ip", event.IP, "rule_id", event.RuleID, "error", err)
		}
	}
	if len(events) > 0 {
		logger.Info("openresty waf events processed", "count", len(events))
	}
}

func startWAFReplayPoller(ctx context.Context, logger *slog.Logger, interval time.Duration, zoneID string, wafReplay *cloudflareevent.Service, cursorStore cursorStateStore) {
	if wafReplay == nil {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		since := loadWAFReplayCursor(ctx, logger, cursorStore, interval)

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			since = runWAFReplayIteration(ctx, logger, zoneID, wafReplay, cursorStore, since, time.Now().UTC())

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func runWAFReplayIteration(ctx context.Context, logger *slog.Logger, zoneID string, wafReplay *cloudflareevent.Service, cursorStore cursorStateStore, since time.Time, now time.Time) time.Time {
	querySince := replayQuerySince(since, cloudflareReplayOverlap)
	report, err := wafReplay.ProcessSince(ctx, zoneID, querySince)
	if err != nil {
		logger.Warn("cloudflare waf replay failed", "error", err)
		return since
	}
	if report.Fetched > 0 {
		logger.Info("cloudflare waf replay processed",
			"fetched", report.Fetched,
			"classified", report.Classified,
			"reported", report.Reported,
			"suppressed", report.Suppressed,
		)
	}
	nextCursor := nextWAFReplayCursor(report, since, now)
	if cursorStore != nil {
		if err := cursorStore.Save(ctx, "cloudflare_waf_since", nextCursor); err != nil {
			logger.Warn("cloudflare waf replay cursor save failed", "error", err)
			return since
		}
	}
	return nextCursor
}

func loadWAFReplayCursor(ctx context.Context, logger *slog.Logger, cursorStore cursorStateStore, interval time.Duration) time.Time {
	since := time.Now().UTC().Add(-interval)
	if cursorStore == nil {
		return since
	}
	persisted, ok, err := cursorStore.Load(ctx, "cloudflare_waf_since")
	if err != nil {
		logger.Warn("cloudflare waf replay cursor load failed", "error", err)
		return since
	}
	if ok {
		return persisted.UTC()
	}
	return since
}

func replayQuerySince(since time.Time, overlap time.Duration) time.Time {
	if since.IsZero() {
		return since
	}
	if overlap <= 0 {
		return since.UTC()
	}
	return since.UTC().Add(-overlap)
}

func nextWAFReplayCursor(report cloudflareevent.ProcessingReport, previous time.Time, now time.Time) time.Time {
	if report.HighWatermark.After(previous) {
		return report.HighWatermark.UTC()
	}
	if now.After(previous) {
		return now.UTC()
	}
	return previous.UTC()
}

func runDaemonWithLocker(ctx context.Context, logger *slog.Logger, orch *pipeline.Orchestrator, collector *status.Collector, j journal.JournalStore, qStore *quarantine.Store, store *state.StateStore, sm *engine.StateMachine, dm *memory.Store, cm *cooldown.Manager, rec *recorder.Recorder, br *registry.Registry, am *activation.Manager, fr *federation.Resolver, adm *admission.Controller, evidence reporting.EvidenceStore, ownershipRepo *sqlite.OwnershipRepository, p *pool.Pool, outboxWorker *reporting.OutboxWorker, stateDir string, interval time.Duration, metricsAddr string, zoneID string, wafReplay *cloudflareevent.Service, cursorStore *sqlite.CursorStore, quotaRefreshers *quotaRefreshers, bundle *wafBundle, acquireLock bool) {
	logger.Info("starting in daemon mode", "state_dir", stateDir, "interval", interval, "metrics_addr", metricsAddr)
	var ownershipLineage *ownership.LineageQueryService
	if ownershipRepo != nil {
		ownershipLineage = ownership.NewLineageQueryService(ownershipRepo)
	}
	srv, apiErr := startAPIServer(logger, collector, j, qStore, orch, p, sm, dm, rec, br, am, fr, adm, evidence, ownershipLineage, metricsAddr)
	if apiErr != nil {
		logger.Warn("admin API server unavailable — scheduler and security components will continue",
			"error", apiErr,
			"hint", "set CF_SYNC_API_TOKEN or CF_SYNC_API_TOKEN_FILE to enable the REST API")
	}

	if acquireLock {
		// Acquire daemon lock
		lockFile := filepath.Join(stateDir, "security-automation-go.pid")
		locker, err := lock.NewFileLock(lockFile)
		if err != nil {
			logger.Error("failed to create daemon lock", "error", err)
			os.Exit(1)
		}

		if err := locker.Acquire(); err != nil {
			if lockErr, ok := err.(lock.PIDLockedError); ok {
				logger.Error("failed to acquire daemon lock: another instance is running", "pid", lockErr.PID)
			} else {
				logger.Error("failed to acquire daemon lock", "error", err)
			}
			os.Exit(1)
		}
		defer locker.Release()
		logger.Info("daemon lock acquired", "lock_file", lockFile)
	}

	s := stateful_scheduler.New(store, orch, sm, cm, logger, interval)
	defer s.Stop()
	childCtx, cancel := newDaemonContext(ctx, logger, srv)
	defer cancel()
	startWAFReplayPoller(childCtx, logger, interval, zoneID, wafReplay, cursorStore)
	startCrowdSecOpenRestyPoller(childCtx, logger, interval, bundle)
	if quotaRefreshers != nil {
		quotaRefreshers.start(childCtx, logger)
	}
	if outboxWorker != nil {
		go func() {
			if err := outboxWorker.Run(childCtx); err != nil && err != context.Canceled {
				logger.Warn("abuseipdb report outbox retry failed", "error", err)
			}
		}()
	}
	if err := s.Start(childCtx, os.Getenv("CF_ZONE_ID")); err != nil {
		if errors.Is(err, context.Canceled) {
			return
		}
		logger.Error("daemon error", "error", err)
		os.Exit(1)
	}
}
